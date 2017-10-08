package driver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-plugin"
	"github.com/mitchellh/mapstructure"

	"github.com/hashicorp/nomad/client/config"
	"github.com/hashicorp/nomad/client/driver/env"
	"github.com/hashicorp/nomad/client/driver/executor"
	dstructs "github.com/hashicorp/nomad/client/driver/structs"
	"github.com/hashicorp/nomad/client/fingerprint"
	cstructs "github.com/hashicorp/nomad/client/structs"
	"github.com/hashicorp/nomad/helper"
	"github.com/hashicorp/nomad/helper/fields"
	"github.com/hashicorp/nomad/nomad/structs"
)

const (
	// The key populated in Node Attributes to indicate presence of the Dotnet
	// driver
	dotnetDriverAttr = "driver.dotnet"
)

// DotnetDriver is a simple driver to execute applications packaged in zip files.
// It literally just fork/execs tasks with the dotnet command.
type DotnetDriver struct {
	DriverContext
	fingerprint.StaticFingerprinter

	// A tri-state boolean to know if the fingerprinting has happened and
	// whether it has been successful
	fingerprintSuccess *bool
}

type DotnetDriverConfig struct {
	DllPath   string   `mapstructure:"dll_path"`
	Args      []string `mapstructure:"args"`
}

// dotnetHandle is returned from Start/Open as a handle to the PID
type dotnetHandle struct {
	pluginClient    *plugin.Client
	userPid         int
	executor        executor.Executor
	isolationConfig *dstructs.IsolationConfig
	taskDir         string

	killTimeout    time.Duration
	maxKillTimeout time.Duration
	version        string
	logger         *log.Logger
	waitCh         chan *dstructs.WaitResult
	doneCh         chan struct{}
}

// NewDotnetDriver is used to create a new exec driver
func NewDotnetDriver(ctx *DriverContext) Driver {
	return &DotnetDriver{DriverContext: *ctx}
}

// Validate is used to validate the driver configuration
func (d *DotnetDriver) Validate(config map[string]interface{}) error {
	fd := &fields.FieldData{
		Raw: config,
		Schema: map[string]*fields.FieldSchema{
			"dll_path": &fields.FieldSchema{
				Type: fields.TypeString,
			},
			"args": &fields.FieldSchema{
				Type: fields.TypeArray,
			},
		},
	}

	if err := fd.Validate(); err != nil {
		return err
	}

	return nil
}

func (d *DotnetDriver) Abilities() DriverAbilities {
	return DriverAbilities{
		SendSignals: true,
		Exec:        true,
	}
}

func (d *DotnetDriver) Fingerprint(cfg *config.Config, node *structs.Node) (bool, error) {
	// Only enable if we are root and cgroups are mounted when running on linux systems.
	if runtime.GOOS == "linux" && (syscall.Geteuid() != 0 || !cgroupsMounted(node)) {
		if d.fingerprintSuccess == nil || *d.fingerprintSuccess {
			d.logger.Printf("[DEBUG] driver.dotnet: root priviledges and mounted cgroups required on linux, disabling")
		}
		delete(node.Attributes, "driver.dotnet")
		d.fingerprintSuccess = helper.BoolToPtr(false)
		return false, nil
	}

	// Find dotnet version
	var out bytes.Buffer
	var erOut bytes.Buffer
	env := os.Environ()
	env = append(env, "DOTNET_PRINT_TELEMETRY_MESSAGE=0", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1")
	cmd := exec.Command("dotnet", "--version")
	cmd.Stdout = &out
	cmd.Stderr = &erOut
	cmd.Env = env
	err := cmd.Run()
	if err != nil {
		// assume Dotnet wasn't found
		delete(node.Attributes, dotnetDriverAttr)
		d.fingerprintSuccess = helper.BoolToPtr(false)
		return false, nil
	}

	// 'dotnet --version' returns output on Stderr typically.
	// Check stdout, but it's probably empty
	var infoString string
	if out.String() != "" {
		infoString = out.String()
	}

	if erOut.String() != "" {
		infoString = erOut.String()
	}

	if infoString == "" {
		if d.fingerprintSuccess == nil || *d.fingerprintSuccess {
			d.logger.Println("[WARN] driver.dotnet: error parsing Dotnet version information, aborting")
		}
		delete(node.Attributes, dotnetDriverAttr)
		d.fingerprintSuccess = helper.BoolToPtr(false)
		d.logger.Println("[DEBUG] driver.dotnet: cant determine version")
		return false, nil
	}

	node.Attributes[dotnetDriverAttr] = "1"
	node.Attributes["driver.dotnet.version"] = infoString
	d.fingerprintSuccess = helper.BoolToPtr(true)
	d.logger.Println("[INFO] driver.dotnet: successfully fingerprinted")

	return true, nil
}

func (d *DotnetDriver) Prestart(*ExecContext, *structs.Task) (*PrestartResponse, error) {
	return nil, nil
}

func NewDotnetDriverConfig(task *structs.Task, env *env.TaskEnv) (*DotnetDriverConfig, error) {
	var driverConfig DotnetDriverConfig
	if err := mapstructure.WeakDecode(task.Config, &driverConfig); err != nil {
		return nil, err
	}

	// Interpolate everything
	driverConfig.DllPath = env.ReplaceEnv(driverConfig.DllPath)
	driverConfig.Args = env.ParseAndReplace(driverConfig.Args)

	// Validate
	dllSpecified := driverConfig.DllPath != ""
	if !dllSpecified {
		return nil, fmt.Errorf("dll_path or class must be specified")
	}

	return &driverConfig, nil
}

func (d *DotnetDriver) Start(ctx *ExecContext, task *structs.Task) (*StartResponse, error) {
	driverConfig, err := NewDotnetDriverConfig(task, ctx.TaskEnv)
	if err != nil {
		return nil, err
	}

	args := []string{}

	// Add the dll
	if driverConfig.DllPath != "" {
		args = append(args, "exec", driverConfig.DllPath)
	}

	// Add any args
	if len(driverConfig.Args) != 0 {
		args = append(args, driverConfig.Args...)
	}

	pluginLogFile := filepath.Join(ctx.TaskDir.Dir, "executor.out")
	executorConfig := &dstructs.ExecutorConfig{
		LogFile:  pluginLogFile,
		LogLevel: d.config.LogLevel,
	}

	execIntf, pluginClient, err := createExecutor(d.config.LogOutput, d.config, executorConfig)
	if err != nil {
		return nil, err
	}
	
	ctx.TaskEnv.EnvMap["DOTNET_PRINT_TELEMETRY_MESSAGE"] = "0"
	ctx.TaskEnv.EnvMap["DOTNET_SKIP_FIRST_TIME_EXPERIENCE"] = "1"

	// Set the context
	executorCtx := &executor.ExecutorContext{
		TaskEnv: ctx.TaskEnv,
		Driver:  "dotnet",
		AllocID: d.DriverContext.allocID,
		Task:    task,
		TaskDir: ctx.TaskDir.Dir,
		LogDir:  ctx.TaskDir.LogDir,
	}
	if err := execIntf.SetContext(executorCtx); err != nil {
		pluginClient.Kill()
		return nil, fmt.Errorf("failed to set executor context: %v", err)
	}

	absPath, err := GetAbsolutePath("dotnet")
	if err != nil {
		return nil, err
	}

	execCmd := &executor.ExecCommand{
		Cmd:            absPath,
		Args:           args,
		FSIsolation:    true,
		ResourceLimits: true,
		User:           getExecutorUser(task),
	}
	ps, err := execIntf.LaunchCmd(execCmd)
	if err != nil {
		pluginClient.Kill()
		return nil, err
	}
	d.logger.Printf("[DEBUG] driver.dotnet: started process with pid: %v", ps.Pid)

	// Return a driver handle
	maxKill := d.DriverContext.config.MaxKillTimeout
	h := &dotnetHandle{
		pluginClient:    pluginClient,
		executor:        execIntf,
		userPid:         ps.Pid,
		isolationConfig: ps.IsolationConfig,
		taskDir:         ctx.TaskDir.Dir,
		killTimeout:     GetKillTimeout(task.KillTimeout, maxKill),
		maxKillTimeout:  maxKill,
		version:         d.config.Version.VersionNumber(),
		logger:          d.logger,
		doneCh:          make(chan struct{}),
		waitCh:          make(chan *dstructs.WaitResult, 1),
	}
	go h.run()
	return &StartResponse{Handle: h}, nil
}

func (d *DotnetDriver) Cleanup(*ExecContext, *CreatedResources) error { return nil }

type dotnetId struct {
	Version         string
	KillTimeout     time.Duration
	MaxKillTimeout  time.Duration
	PluginConfig    *PluginReattachConfig
	IsolationConfig *dstructs.IsolationConfig
	TaskDir         string
	UserPid         int
}

func (d *DotnetDriver) Open(ctx *ExecContext, handleID string) (DriverHandle, error) {
	id := &dotnetId{}
	if err := json.Unmarshal([]byte(handleID), id); err != nil {
		return nil, fmt.Errorf("Failed to parse handle '%s': %v", handleID, err)
	}

	pluginConfig := &plugin.ClientConfig{
		Reattach: id.PluginConfig.PluginConfig(),
	}
	exec, pluginClient, err := createExecutorWithConfig(pluginConfig, d.config.LogOutput)
	if err != nil {
		merrs := new(multierror.Error)
		merrs.Errors = append(merrs.Errors, err)
		d.logger.Println("[ERR] driver.dotnet: error connecting to plugin so destroying plugin pid and user pid")
		if e := destroyPlugin(id.PluginConfig.Pid, id.UserPid); e != nil {
			merrs.Errors = append(merrs.Errors, fmt.Errorf("error destroying plugin and userpid: %v", e))
		}
		if id.IsolationConfig != nil {
			ePid := pluginConfig.Reattach.Pid
			if e := executor.ClientCleanup(id.IsolationConfig, ePid); e != nil {
				merrs.Errors = append(merrs.Errors, fmt.Errorf("destroying resource container failed: %v", e))
			}
		}

		return nil, fmt.Errorf("error connecting to plugin: %v", merrs.ErrorOrNil())
	}

	ver, _ := exec.Version()
	d.logger.Printf("[DEBUG] driver.dotnet: version of executor: %v", ver.Version)

	// Return a driver handle
	h := &dotnetHandle{
		pluginClient:    pluginClient,
		executor:        exec,
		userPid:         id.UserPid,
		isolationConfig: id.IsolationConfig,
		logger:          d.logger,
		version:         id.Version,
		killTimeout:     id.KillTimeout,
		maxKillTimeout:  id.MaxKillTimeout,
		doneCh:          make(chan struct{}),
		waitCh:          make(chan *dstructs.WaitResult, 1),
	}
	go h.run()
	return h, nil
}

func (h *dotnetHandle) ID() string {
	id := dotnetId{
		Version:         h.version,
		KillTimeout:     h.killTimeout,
		MaxKillTimeout:  h.maxKillTimeout,
		PluginConfig:    NewPluginReattachConfig(h.pluginClient.ReattachConfig()),
		UserPid:         h.userPid,
		IsolationConfig: h.isolationConfig,
		TaskDir:         h.taskDir,
	}

	data, err := json.Marshal(id)
	if err != nil {
		h.logger.Printf("[ERR] driver.dotnet: failed to marshal ID to JSON: %s", err)
	}
	return string(data)
}

func (h *dotnetHandle) WaitCh() chan *dstructs.WaitResult {
	return h.waitCh
}

func (h *dotnetHandle) Update(task *structs.Task) error {
	// Store the updated kill timeout.
	h.killTimeout = GetKillTimeout(task.KillTimeout, h.maxKillTimeout)
	h.executor.UpdateTask(task)

	// Update is not possible
	return nil
}

func (h *dotnetHandle) Exec(ctx context.Context, cmd string, args []string) ([]byte, int, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		// No deadline set on context; default to 1 minute
		deadline = time.Now().Add(time.Minute)
	}
	return h.executor.Exec(deadline, cmd, args)
}

func (h *dotnetHandle) Signal(s os.Signal) error {
	return h.executor.Signal(s)
}

func (h *dotnetHandle) Kill() error {
	if err := h.executor.ShutDown(); err != nil {
		if h.pluginClient.Exited() {
			return nil
		}
		return fmt.Errorf("executor Shutdown failed: %v", err)
	}

	select {
	case <-h.doneCh:
	case <-time.After(h.killTimeout):
		if h.pluginClient.Exited() {
			break
		}
		if err := h.executor.Exit(); err != nil {
			return fmt.Errorf("executor Exit failed: %v", err)
		}

	}
	return nil
}

func (h *dotnetHandle) Stats() (*cstructs.TaskResourceUsage, error) {
	return h.executor.Stats()
}

func (h *dotnetHandle) run() {
	ps, werr := h.executor.Wait()
	close(h.doneCh)
	if ps.ExitCode == 0 && werr != nil {
		if h.isolationConfig != nil {
			ePid := h.pluginClient.ReattachConfig().Pid
			if e := executor.ClientCleanup(h.isolationConfig, ePid); e != nil {
				h.logger.Printf("[ERR] driver.dotnet: destroying resource container failed: %v", e)
			}
		} else {
			if e := killProcess(h.userPid); e != nil {
				h.logger.Printf("[ERR] driver.dotnet: error killing user process: %v", e)
			}
		}
	}

	// Exit the executor
	h.executor.Exit()
	h.pluginClient.Kill()

	// Send the results
	h.waitCh <- &dstructs.WaitResult{ExitCode: ps.ExitCode, Signal: ps.Signal, Err: werr}
	close(h.waitCh)
}
