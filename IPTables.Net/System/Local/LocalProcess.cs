using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.Remoting;

namespace IPTables.Net.System.Local
{
    internal class LocalProcess : ISystemProcess
    {
        private readonly Process _process;
#if DEBUG
        private readonly SshCommand _command;
#endif

        public LocalProcess(Process process)
        {
            _process = process;
        }

#if DEBUG
        public GreProcess(SshCommand process)
        {
            _command = process;
        }
#endif

        public static LocalProcess Start(ProcessStartInfo info)
        {
            Console.WriteLine(info.FileName + " " + info.Arguments);
#if DEBUG
            var e = GreSsh.Instance.Execute(info.FileName + " " + info.Arguments);
            return new GreProcess(e);
#else
            info.RedirectStandardOutput = true;
            info.RedirectStandardError = true;

            info.UseShellExecute = false;
            info.Arguments = "-c \"" + info.FileName + " " + info.Arguments + "\"";
            info.FileName = "/bin/bash";
            return new LocalProcess(Process.Start(info));
#endif
        }

        /// <summary>
        /// Retrieves the current lifetime service object that controls the lifetime policy for this instance.
        /// </summary>
        /// <returns>
        /// An object of type <see cref="T:System.Runtime.Remoting.Lifetime.ILease"/> used to control the lifetime policy for this instance.
        /// </returns>
        /// <exception cref="T:System.Security.SecurityException">The immediate caller does not have infrastructure permission. </exception><filterpriority>2</filterpriority><PermissionSet><IPermission class="System.Security.Permissions.SecurityPermission, mscorlib, Version=2.0.3600.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" version="1" Flags="RemotingConfiguration, Infrastructure"/></PermissionSet>
        public object GetLifetimeService()
        {
            return _process.GetLifetimeService();
        }

        /// <summary>
        /// Obtains a lifetime service object to control the lifetime policy for this instance.
        /// </summary>
        /// <returns>
        /// An object of type <see cref="T:System.Runtime.Remoting.Lifetime.ILease"/> used to control the lifetime policy for this instance. This is the current lifetime service object for this instance if one exists; otherwise, a new lifetime service object initialized to the value of the <see cref="P:System.Runtime.Remoting.Lifetime.LifetimeServices.LeaseManagerPollTime"/> property.
        /// </returns>
        /// <exception cref="T:System.Security.SecurityException">The immediate caller does not have infrastructure permission. </exception><filterpriority>2</filterpriority><PermissionSet><IPermission class="System.Security.Permissions.SecurityPermission, mscorlib, Version=2.0.3600.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" version="1" Flags="RemotingConfiguration, Infrastructure"/></PermissionSet>
        public object InitializeLifetimeService()
        {
            return _process.InitializeLifetimeService();
        }

        /// <summary>
        /// Creates an object that contains all the relevant information required to generate a proxy used to communicate with a remote object.
        /// </summary>
        /// <returns>
        /// Information required to generate a proxy.
        /// </returns>
        /// <param name="requestedType">The <see cref="T:System.Type"/> of the object that the new <see cref="T:System.Runtime.Remoting.ObjRef"/> will reference. </param><exception cref="T:System.Runtime.Remoting.RemotingException">This instance is not a valid remoting object. </exception><exception cref="T:System.Security.SecurityException">The immediate caller does not have infrastructure permission. </exception><filterpriority>2</filterpriority><PermissionSet><IPermission class="System.Security.Permissions.SecurityPermission, mscorlib, Version=2.0.3600.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" version="1" Flags="Infrastructure"/></PermissionSet>
        public ObjRef CreateObjRef(Type requestedType)
        {
            return _process.CreateObjRef(requestedType);
        }

        /// <summary>
        /// Releases all resources used by the <see cref="T:System.ComponentModel.Component"/>.
        /// </summary>
        public void Dispose()
        {
            _process.Dispose();
        }

        /// <summary>
        /// Gets or sets the <see cref="T:System.ComponentModel.ISite"/> of the <see cref="T:System.ComponentModel.Component"/>.
        /// </summary>
        /// <returns>
        /// The <see cref="T:System.ComponentModel.ISite"/> associated with the <see cref="T:System.ComponentModel.Component"/>, or null if the <see cref="T:System.ComponentModel.Component"/> is not encapsulated in an <see cref="T:System.ComponentModel.IContainer"/>, the <see cref="T:System.ComponentModel.Component"/> does not have an <see cref="T:System.ComponentModel.ISite"/> associated with it, or the <see cref="T:System.ComponentModel.Component"/> is removed from its <see cref="T:System.ComponentModel.IContainer"/>.
        /// </returns>
        public ISite Site
        {
            get { return _process.Site; }
            set { _process.Site = value; }
        }

        /// <summary>
        /// Gets the <see cref="T:System.ComponentModel.IContainer"/> that contains the <see cref="T:System.ComponentModel.Component"/>.
        /// </summary>
        /// <returns>
        /// The <see cref="T:System.ComponentModel.IContainer"/> that contains the <see cref="T:System.ComponentModel.Component"/>, if any, or null if the <see cref="T:System.ComponentModel.Component"/> is not encapsulated in an <see cref="T:System.ComponentModel.IContainer"/>.
        /// </returns>
        public IContainer Container
        {
            get { return _process.Container; }
        }

        public event EventHandler Disposed
        {
            add { _process.Disposed += value; }
            remove { _process.Disposed -= value; }
        }

        /// <summary>
        /// Closes a process that has a user interface by sending a close message to its main window.
        /// </summary>
        /// <returns>
        /// true if the close message was successfully sent; false if the associated process does not have a main window or if the main window is disabled (for example if a modal dialog is being shown).
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me); set the <see cref="P:System.Diagnostics.ProcessStartInfo.UseShellExecute"/> property to false to access this property on Windows 98 and Windows Me.</exception><exception cref="T:System.InvalidOperationException">The process has already exited. -or-No process is associated with this <see cref="T:System.Diagnostics.Process"/> object.</exception><filterpriority>1</filterpriority>
        public bool CloseMainWindow()
        {
            return _process.CloseMainWindow();
        }

        /// <summary>
        /// Frees all the resources that are associated with this component.
        /// </summary>
        /// <filterpriority>2</filterpriority>
        public void Close()
        {
            _process.Close();
        }

        /// <summary>
        /// Discards any information about the associated process that has been cached inside the process component.
        /// </summary>
        /// <filterpriority>1</filterpriority>
        public void Refresh()
        {
            _process.Refresh();
        }

        /// <summary>
        /// Starts (or reuses) the process resource that is specified by the <see cref="P:System.Diagnostics.Process.StartInfo"/> property of this <see cref="T:System.Diagnostics.Process"/> component and associates it with the component.
        /// </summary>
        /// <returns>
        /// true if a process resource is started; false if no new process resource is started (for example, if an existing process is reused).
        /// </returns>
        /// <exception cref="T:System.InvalidOperationException">No file name was specified in the <see cref="T:System.Diagnostics.Process"/> component's <see cref="P:System.Diagnostics.Process.StartInfo"/>.-or- The <see cref="P:System.Diagnostics.ProcessStartInfo.UseShellExecute"/> member of the <see cref="P:System.Diagnostics.Process.StartInfo"/> property is true while <see cref="P:System.Diagnostics.ProcessStartInfo.RedirectStandardInput"/>, <see cref="P:System.Diagnostics.ProcessStartInfo.RedirectStandardOutput"/>, or <see cref="P:System.Diagnostics.ProcessStartInfo.RedirectStandardError"/> is true. </exception><exception cref="T:System.ComponentModel.Win32Exception">There was an error in opening the associated file. </exception><exception cref="T:System.ObjectDisposedException">The process object has already been disposed. </exception><filterpriority>1</filterpriority>
        public bool Start()
        {
            return _process.Start();
        }

        /// <summary>
        /// Immediately stops the associated process.
        /// </summary>
        /// <exception cref="T:System.ComponentModel.Win32Exception">The associated process could not be terminated. -or-The process is terminating.-or- The associated process is a Win16 executable.</exception><exception cref="T:System.NotSupportedException">You are attempting to call <see cref="M:System.Diagnostics.Process.Kill"/> for a process that is running on a remote computer. The method is available only for processes running on the local computer.</exception><exception cref="T:System.InvalidOperationException">The process has already exited. -or-There is no process associated with this <see cref="T:System.Diagnostics.Process"/> object.</exception><filterpriority>1</filterpriority>
        public void Kill()
        {
            _process.Kill();
        }

        /// <summary>
        /// Instructs the <see cref="T:System.Diagnostics.Process"/> component to wait the specified number of milliseconds for the associated process to exit.
        /// </summary>
        /// <returns>
        /// true if the associated process has exited; otherwise, false.
        /// </returns>
        /// <param name="milliseconds">The amount of time, in milliseconds, to wait for the associated process to exit. The maximum is the largest possible value of a 32-bit integer, which represents infinity to the operating system. </param><exception cref="T:System.ComponentModel.Win32Exception">The wait setting could not be accessed. </exception><exception cref="T:System.SystemException">No process <see cref="P:System.Diagnostics.Process.Id"/> has been set, and a <see cref="P:System.Diagnostics.Process.Handle"/> from which the <see cref="P:System.Diagnostics.Process.Id"/> property can be determined does not exist.-or- There is no process associated with this <see cref="T:System.Diagnostics.Process"/> object.-or- You are attempting to call <see cref="M:System.Diagnostics.Process.WaitForExit(System.Int32)"/> for a process that is running on a remote computer. This method is available only for processes that are running on the local computer. </exception><filterpriority>1</filterpriority>
        public bool WaitForExit(int milliseconds)
        {
            return _process.WaitForExit(milliseconds);
        }

        /// <summary>
        /// Instructs the <see cref="T:System.Diagnostics.Process"/> component to wait indefinitely for the associated process to exit.
        /// </summary>
        /// <exception cref="T:System.ComponentModel.Win32Exception">The wait setting could not be accessed. </exception><exception cref="T:System.SystemException">No process <see cref="P:System.Diagnostics.Process.Id"/> has been set, and a <see cref="P:System.Diagnostics.Process.Handle"/> from which the <see cref="P:System.Diagnostics.Process.Id"/> property can be determined does not exist.-or- There is no process associated with this <see cref="T:System.Diagnostics.Process"/> object.-or- You are attempting to call <see cref="M:System.Diagnostics.Process.WaitForExit"/> for a process that is running on a remote computer. This method is available only for processes that are running on the local computer. </exception><filterpriority>1</filterpriority>
        public void WaitForExit()
        {
#if DEBUG
            return;
#endif
            _process.WaitForExit();
        }

        /// <summary>
        /// Causes the <see cref="T:System.Diagnostics.Process"/> component to wait the specified number of milliseconds for the associated process to enter an idle state. This overload applies only to processes with a user interface and, therefore, a message loop.
        /// </summary>
        /// <returns>
        /// true if the associated process has reached an idle state; otherwise, false.
        /// </returns>
        /// <param name="milliseconds">A value of 1 to <see cref="F:System.Int32.MaxValue"/> that specifies the amount of time, in milliseconds, to wait for the associated process to become idle. A value of 0 specifies an immediate return, and a value of -1 specifies an infinite wait. </param><exception cref="T:System.InvalidOperationException">The process does not have a graphical interface.-or-An unknown error occurred. The process failed to enter an idle state.-or-The process has already exited. -or-No process is associated with this <see cref="T:System.Diagnostics.Process"/> object.</exception><filterpriority>1</filterpriority>
        public bool WaitForInputIdle(int milliseconds)
        {
            return _process.WaitForInputIdle(milliseconds);
        }

        /// <summary>
        /// Causes the <see cref="T:System.Diagnostics.Process"/> component to wait indefinitely for the associated process to enter an idle state. This overload applies only to processes with a user interface and, therefore, a message loop.
        /// </summary>
        /// <returns>
        /// true if the associated process has reached an idle state.
        /// </returns>
        /// <exception cref="T:System.InvalidOperationException">The process does not have a graphical interface.-or-An unknown error occurred. The process failed to enter an idle state.-or-The process has already exited. -or-No process is associated with this <see cref="T:System.Diagnostics.Process"/> object.</exception><filterpriority>1</filterpriority>
        public bool WaitForInputIdle()
        {
            return _process.WaitForInputIdle();
        }

        /// <summary>
        /// Begins asynchronous read operations on the redirected <see cref="P:System.Diagnostics.Process.StandardOutput"/> stream of the application.
        /// </summary>
        /// <exception cref="T:System.InvalidOperationException">The <see cref="P:System.Diagnostics.ProcessStartInfo.RedirectStandardOutput"/> property is false.- or - An asynchronous read operation is already in progress on the <see cref="P:System.Diagnostics.Process.StandardOutput"/> stream.- or - The <see cref="P:System.Diagnostics.Process.StandardOutput"/> stream has been used by a synchronous read operation. </exception><filterpriority>2</filterpriority>
        public void BeginOutputReadLine()
        {
            _process.BeginOutputReadLine();
        }

        /// <summary>
        /// Begins asynchronous read operations on the redirected <see cref="P:System.Diagnostics.Process.StandardError"/> stream of the application.
        /// </summary>
        /// <exception cref="T:System.InvalidOperationException">The <see cref="P:System.Diagnostics.ProcessStartInfo.RedirectStandardError"/> property is false.- or - An asynchronous read operation is already in progress on the <see cref="P:System.Diagnostics.Process.StandardError"/> stream.- or - The <see cref="P:System.Diagnostics.Process.StandardError"/> stream has been used by a synchronous read operation. </exception><filterpriority>2</filterpriority>
        public void BeginErrorReadLine()
        {
            _process.BeginErrorReadLine();
        }

        /// <summary>
        /// Cancels the asynchronous read operation on the redirected <see cref="P:System.Diagnostics.Process.StandardOutput"/> stream of an application.
        /// </summary>
        /// <exception cref="T:System.InvalidOperationException">The <see cref="P:System.Diagnostics.Process.StandardOutput"/> stream is not enabled for asynchronous read operations. </exception><filterpriority>2</filterpriority>
        public void CancelOutputRead()
        {
            _process.CancelOutputRead();
        }

        /// <summary>
        /// Cancels the asynchronous read operation on the redirected <see cref="P:System.Diagnostics.Process.StandardError"/> stream of an application.
        /// </summary>
        /// <exception cref="T:System.InvalidOperationException">The <see cref="P:System.Diagnostics.Process.StandardError"/> stream is not enabled for asynchronous read operations. </exception><filterpriority>2</filterpriority>
        public void CancelErrorRead()
        {
            _process.CancelErrorRead();
        }

        /// <summary>
        /// Gets the base priority of the associated process.
        /// </summary>
        /// <returns>
        /// The base priority, which is computed from the <see cref="P:System.Diagnostics.Process.PriorityClass"/> of the associated process.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me); set the <see cref="P:System.Diagnostics.ProcessStartInfo.UseShellExecute"/> property to false to access this property on Windows 98 and Windows Me.</exception><exception cref="T:System.InvalidOperationException">The process has exited.-or- The process has not started, so there is no process ID. </exception><filterpriority>2</filterpriority>
        public int BasePriority
        {
            get { return _process.BasePriority; }
        }

        /// <summary>
        /// Gets the value that the associated process specified when it terminated.
        /// </summary>
        /// <returns>
        /// The code that the associated process specified when it terminated.
        /// </returns>
        /// <exception cref="T:System.InvalidOperationException">The process has not exited.-or- The process <see cref="P:System.Diagnostics.Process.Handle"/> is not valid. </exception><exception cref="T:System.NotSupportedException">You are trying to access the <see cref="P:System.Diagnostics.Process.ExitCode"/> property for a process that is running on a remote computer. This property is available only for processes that are running on the local computer.</exception><filterpriority>1</filterpriority>
        public int ExitCode
        {
            get { return _process.ExitCode; }
        }

        /// <summary>
        /// Gets a value indicating whether the associated process has been terminated.
        /// </summary>
        /// <returns>
        /// true if the operating system process referenced by the <see cref="T:System.Diagnostics.Process"/> component has terminated; otherwise, false.
        /// </returns>
        /// <exception cref="T:System.InvalidOperationException">There is no process associated with the object. </exception><exception cref="T:System.ComponentModel.Win32Exception">The exit code for the process could not be retrieved. </exception><exception cref="T:System.NotSupportedException">You are trying to access the <see cref="P:System.Diagnostics.Process.HasExited"/> property for a process that is running on a remote computer. This property is available only for processes that are running on the local computer.</exception><filterpriority>1</filterpriority>
        public bool HasExited
        {
            get { return _process.HasExited; }
        }

        /// <summary>
        /// Gets the time that the associated process exited.
        /// </summary>
        /// <returns>
        /// A <see cref="T:System.DateTime"/> that indicates when the associated process was terminated.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property. </exception><exception cref="T:System.NotSupportedException">You are trying to access the <see cref="P:System.Diagnostics.Process.ExitTime"/> property for a process that is running on a remote computer. This property is available only for processes that are running on the local computer.</exception><filterpriority>1</filterpriority>
        public DateTime ExitTime
        {
            get { return _process.ExitTime; }
        }

        /// <summary>
        /// Gets the native handle of the associated process.
        /// </summary>
        /// <returns>
        /// The handle that the operating system assigned to the associated process when the process was started. The system uses this handle to keep track of process attributes.
        /// </returns>
        /// <exception cref="T:System.InvalidOperationException">The process has not been started or has exited. The <see cref="P:System.Diagnostics.Process.Handle"/> property cannot be read because there is no process associated with this <see cref="T:System.Diagnostics.Process"/> instance.-or- The <see cref="T:System.Diagnostics.Process"/> instance has been attached to a running process but you do not have the necessary permissions to get a handle with full access rights. </exception><exception cref="T:System.NotSupportedException">You are trying to access the <see cref="P:System.Diagnostics.Process.Handle"/> property for a process that is running on a remote computer. This property is available only for processes that are running on the local computer.</exception><filterpriority>1</filterpriority>
        public IntPtr Handle
        {
            get { return _process.Handle; }
        }

        /// <summary>
        /// Gets the number of handles opened by the process.
        /// </summary>
        /// <returns>
        /// The number of operating system handles the process has opened.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me); set the <see cref="P:System.Diagnostics.ProcessStartInfo.UseShellExecute"/> property to false to access this property on Windows 98 and Windows Me.</exception><filterpriority>2</filterpriority>
        public int HandleCount
        {
            get { return _process.HandleCount; }
        }

        /// <summary>
        /// Gets the unique identifier for the associated process.
        /// </summary>
        /// <returns>
        /// The system-generated unique identifier of the process that is referenced by this <see cref="T:System.Diagnostics.Process"/> instance.
        /// </returns>
        /// <exception cref="T:System.InvalidOperationException">The process's <see cref="P:System.Diagnostics.Process.Id"/> property has not been set.-or- There is no process associated with this <see cref="T:System.Diagnostics.Process"/> object. </exception><exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me); set the <see cref="P:System.Diagnostics.ProcessStartInfo.UseShellExecute"/> property to false to access this property on Windows 98 and Windows Me.</exception><filterpriority>1</filterpriority>
        public int Id
        {
            get { return _process.Id; }
        }

        /// <summary>
        /// Gets the name of the computer the associated process is running on.
        /// </summary>
        /// <returns>
        /// The name of the computer that the associated process is running on.
        /// </returns>
        /// <exception cref="T:System.InvalidOperationException">There is no process associated with this <see cref="T:System.Diagnostics.Process"/> object. </exception><filterpriority>1</filterpriority>
        public string MachineName
        {
            get { return _process.MachineName; }
        }

        /// <summary>
        /// Gets the window handle of the main window of the associated process.
        /// </summary>
        /// <returns>
        /// The system-generated window handle of the main window of the associated process.
        /// </returns>
        /// <exception cref="T:System.InvalidOperationException">The <see cref="P:System.Diagnostics.Process.MainWindowHandle"/> is not defined because the process has exited. </exception><exception cref="T:System.NotSupportedException">You are trying to access the <see cref="P:System.Diagnostics.Process.MainWindowHandle"/> property for a process that is running on a remote computer. This property is available only for processes that are running on the local computer.</exception><exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me); set <see cref="P:System.Diagnostics.ProcessStartInfo.UseShellExecute"/> to false to access this property on Windows 98 and Windows Me.</exception><filterpriority>2</filterpriority>
        public IntPtr MainWindowHandle
        {
            get { return _process.MainWindowHandle; }
        }

        /// <summary>
        /// Gets the caption of the main window of the process.
        /// </summary>
        /// <returns>
        /// The main window title of the process.
        /// </returns>
        /// <exception cref="T:System.InvalidOperationException">The <see cref="P:System.Diagnostics.Process.MainWindowTitle"/> property is not defined because the process has exited. </exception><exception cref="T:System.NotSupportedException">You are trying to access the <see cref="P:System.Diagnostics.Process.MainWindowTitle"/> property for a process that is running on a remote computer. This property is available only for processes that are running on the local computer.</exception><exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me); set <see cref="P:System.Diagnostics.ProcessStartInfo.UseShellExecute"/> to false to access this property on Windows 98 and Windows Me.</exception><filterpriority>1</filterpriority>
        public string MainWindowTitle
        {
            get { return _process.MainWindowTitle; }
        }

        /// <summary>
        /// Gets the main module for the associated process.
        /// </summary>
        /// <returns>
        /// The <see cref="T:System.Diagnostics.ProcessModule"/> that was used to start the process.
        /// </returns>
        /// <exception cref="T:System.NotSupportedException">You are trying to access the <see cref="P:System.Diagnostics.Process.MainModule"/> property for a process that is running on a remote computer. This property is available only for processes that are running on the local computer.</exception><exception cref="T:System.ComponentModel.Win32Exception">A 32-bit process is trying to access the modules of a 64-bit process.</exception><exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me); set <see cref="P:System.Diagnostics.ProcessStartInfo.UseShellExecute"/> to false to access this property on Windows 98 and Windows Me.</exception><exception cref="T:System.InvalidOperationException">The process <see cref="P:System.Diagnostics.Process.Id"/> is not available.-or- The process has exited. </exception><filterpriority>1</filterpriority>
        public ProcessModule MainModule
        {
            get { return _process.MainModule; }
        }

        /// <summary>
        /// Gets or sets the maximum allowable working set size for the associated process.
        /// </summary>
        /// <returns>
        /// The maximum working set size that is allowed in memory for the process, in bytes.
        /// </returns>
        /// <exception cref="T:System.ArgumentException">The maximum working set size is invalid. It must be greater than or equal to the minimum working set size.</exception><exception cref="T:System.ComponentModel.Win32Exception">Working set information cannot be retrieved from the associated process resource.-or- The process identifier or process handle is zero because the process has not been started. </exception><exception cref="T:System.NotSupportedException">You are trying to access the <see cref="P:System.Diagnostics.Process.MaxWorkingSet"/> property for a process that is running on a remote computer. This property is available only for processes that are running on the local computer.</exception><exception cref="T:System.InvalidOperationException">The process <see cref="P:System.Diagnostics.Process.Id"/> is not available.-or- The process has exited. </exception><exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property. </exception><filterpriority>2</filterpriority>
        public IntPtr MaxWorkingSet
        {
            get { return _process.MaxWorkingSet; }
            set { _process.MaxWorkingSet = value; }
        }

        /// <summary>
        /// Gets or sets the minimum allowable working set size for the associated process.
        /// </summary>
        /// <returns>
        /// The minimum working set size that is required in memory for the process, in bytes.
        /// </returns>
        /// <exception cref="T:System.ArgumentException">The minimum working set size is invalid. It must be less than or equal to the maximum working set size.</exception><exception cref="T:System.ComponentModel.Win32Exception">Working set information cannot be retrieved from the associated process resource.-or- The process identifier or process handle is zero because the process has not been started. </exception><exception cref="T:System.NotSupportedException">You are trying to access the <see cref="P:System.Diagnostics.Process.MinWorkingSet"/> property for a process that is running on a remote computer. This property is available only for processes that are running on the local computer. </exception><exception cref="T:System.InvalidOperationException">The process <see cref="P:System.Diagnostics.Process.Id"/> is not available.-or- The process has exited.</exception><exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property. </exception><filterpriority>2</filterpriority>
        public IntPtr MinWorkingSet
        {
            get { return _process.MinWorkingSet; }
            set { _process.MinWorkingSet = value; }
        }

        /// <summary>
        /// Gets the modules that have been loaded by the associated process.
        /// </summary>
        /// <returns>
        /// An array of type <see cref="T:System.Diagnostics.ProcessModule"/> that represents the modules that have been loaded by the associated process.
        /// </returns>
        /// <exception cref="T:System.NotSupportedException">You are attempting to access the <see cref="P:System.Diagnostics.Process.Modules"/> property for a process that is running on a remote computer. This property is available only for processes that are running on the local computer. </exception><exception cref="T:System.InvalidOperationException">The process <see cref="P:System.Diagnostics.Process.Id"/> is not available.</exception><exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me); set <see cref="P:System.Diagnostics.ProcessStartInfo.UseShellExecute"/> to false to access this property on Windows 98 and Windows Me.</exception><exception cref="T:System.ComponentModel.Win32Exception">You are attempting to access the <see cref="P:System.Diagnostics.Process.Modules"/> property for either the system process or the idle process. These processes do not have modules.</exception><filterpriority>2</filterpriority>
        public ProcessModuleCollection Modules
        {
            get { return _process.Modules; }
        }

        /// <summary>
        /// Gets the nonpaged system memory size allocated to this process.
        /// </summary>
        /// <returns>
        /// The amount of memory, in bytes, the system has allocated for the associated process that cannot be written to the virtual memory paging file.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property. </exception><filterpriority>2</filterpriority>
        public int NonpagedSystemMemorySize
        {
            get { return _process.NonpagedSystemMemorySize; }
        }

        /// <summary>
        /// Gets the amount of nonpaged system memory allocated for the associated process.
        /// </summary>
        /// <returns>
        /// The amount of system memory, in bytes, allocated for the associated process that cannot be written to the virtual memory paging file.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property.</exception><filterpriority>2</filterpriority>
        public long NonpagedSystemMemorySize64
        {
            get { return _process.NonpagedSystemMemorySize64; }
        }

        /// <summary>
        /// Gets the paged memory size.
        /// </summary>
        /// <returns>
        /// The amount of memory, in bytes, allocated by the associated process that can be written to the virtual memory paging file.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property. </exception><filterpriority>2</filterpriority>
        public int PagedMemorySize
        {
            get { return _process.PagedMemorySize; }
        }

        /// <summary>
        /// Gets the amount of paged memory allocated for the associated process.
        /// </summary>
        /// <returns>
        /// The amount of memory, in bytes, allocated in the virtual memory paging file for the associated process.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property.</exception><filterpriority>2</filterpriority>
        public long PagedMemorySize64
        {
            get { return _process.PagedMemorySize64; }
        }

        /// <summary>
        /// Gets the paged system memory size.
        /// </summary>
        /// <returns>
        /// The amount of memory, in bytes, the system has allocated for the associated process that can be written to the virtual memory paging file.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property. </exception><filterpriority>2</filterpriority>
        public int PagedSystemMemorySize
        {
            get { return _process.PagedSystemMemorySize; }
        }

        /// <summary>
        /// Gets the amount of pageable system memory allocated for the associated process.
        /// </summary>
        /// <returns>
        /// The amount of system memory, in bytes, allocated for the associated process that can be written to the virtual memory paging file.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property.</exception><filterpriority>2</filterpriority>
        public long PagedSystemMemorySize64
        {
            get { return _process.PagedSystemMemorySize64; }
        }

        /// <summary>
        /// Gets the peak paged memory size.
        /// </summary>
        /// <returns>
        /// The maximum amount of memory, in bytes, allocated by the associated process that could be written to the virtual memory paging file.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property. </exception><filterpriority>2</filterpriority>
        public int PeakPagedMemorySize
        {
            get { return _process.PeakPagedMemorySize; }
        }

        /// <summary>
        /// Gets the maximum amount of memory in the virtual memory paging file used by the associated process.
        /// </summary>
        /// <returns>
        /// The maximum amount of memory, in bytes, allocated in the virtual memory paging file for the associated process since it was started.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property.</exception><filterpriority>2</filterpriority>
        public long PeakPagedMemorySize64
        {
            get { return _process.PeakPagedMemorySize64; }
        }

        /// <summary>
        /// Gets the peak working set size for the associated process.
        /// </summary>
        /// <returns>
        /// The maximum amount of physical memory that the associated process has required all at once, in bytes.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property. </exception><filterpriority>2</filterpriority>
        public int PeakWorkingSet
        {
            get { return _process.PeakWorkingSet; }
        }

        /// <summary>
        /// Gets the maximum amount of physical memory used by the associated process.
        /// </summary>
        /// <returns>
        /// The maximum amount of physical memory, in bytes, allocated for the associated process since it was started.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property.</exception><filterpriority>2</filterpriority>
        public long PeakWorkingSet64
        {
            get { return _process.PeakWorkingSet64; }
        }

        /// <summary>
        /// Gets the peak virtual memory size.
        /// </summary>
        /// <returns>
        /// The maximum amount of virtual memory, in bytes, that the associated process has requested.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property. </exception><filterpriority>2</filterpriority>
        public int PeakVirtualMemorySize
        {
            get { return _process.PeakVirtualMemorySize; }
        }

        /// <summary>
        /// Gets the maximum amount of virtual memory used by the associated process.
        /// </summary>
        /// <returns>
        /// The maximum amount of virtual memory, in bytes, allocated for the associated process since it was started.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property.</exception><filterpriority>2</filterpriority>
        public long PeakVirtualMemorySize64
        {
            get { return _process.PeakVirtualMemorySize64; }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the associated process priority should temporarily be boosted by the operating system when the main window has the focus.
        /// </summary>
        /// <returns>
        /// true if dynamic boosting of the process priority should take place for a process when it is taken out of the wait state; otherwise, false. The default is false.
        /// </returns>
        /// <exception cref="T:System.ComponentModel.Win32Exception">Priority boost information could not be retrieved from the associated process resource. </exception><exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property.-or- The process identifier or process handle is zero. (The process has not been started.) </exception><exception cref="T:System.NotSupportedException">You are attempting to access the <see cref="P:System.Diagnostics.Process.PriorityBoostEnabled"/> property for a process that is running on a remote computer. This property is available only for processes that are running on the local computer. </exception><exception cref="T:System.InvalidOperationException">The process <see cref="P:System.Diagnostics.Process.Id"/> is not available.</exception><filterpriority>1</filterpriority>
        public bool PriorityBoostEnabled
        {
            get { return _process.PriorityBoostEnabled; }
            set { _process.PriorityBoostEnabled = value; }
        }

        /// <summary>
        /// Gets or sets the overall priority category for the associated process.
        /// </summary>
        /// <returns>
        /// The priority category for the associated process, from which the <see cref="P:System.Diagnostics.Process.BasePriority"/> of the process is calculated.
        /// </returns>
        /// <exception cref="T:System.ComponentModel.Win32Exception">Process priority information could not be set or retrieved from the associated process resource.-or- The process identifier or process handle is zero. (The process has not been started.) </exception><exception cref="T:System.NotSupportedException">You are attempting to access the <see cref="P:System.Diagnostics.Process.PriorityClass"/> property for a process that is running on a remote computer. This property is available only for processes that are running on the local computer. </exception><exception cref="T:System.InvalidOperationException">The process <see cref="P:System.Diagnostics.Process.Id"/> is not available.</exception><exception cref="T:System.PlatformNotSupportedException">You have set the <see cref="P:System.Diagnostics.Process.PriorityClass"/> to AboveNormal or BelowNormal when using Windows 98 or Windows Millennium Edition (Windows Me). These platforms do not support those values for the priority class. </exception><exception cref="T:System.ComponentModel.InvalidEnumArgumentException">Priority class cannot be set because it does not use a valid value, as defined in the <see cref="T:System.Diagnostics.ProcessPriorityClass"/> enumeration.</exception><filterpriority>1</filterpriority>
        public ProcessPriorityClass PriorityClass
        {
            get { return _process.PriorityClass; }
            set { _process.PriorityClass = value; }
        }

        /// <summary>
        /// Gets the private memory size.
        /// </summary>
        /// <returns>
        /// The number of bytes allocated by the associated process that cannot be shared with other processes.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property. </exception><filterpriority>2</filterpriority>
        public int PrivateMemorySize
        {
            get { return _process.PrivateMemorySize; }
        }

        /// <summary>
        /// Gets the amount of private memory allocated for the associated process.
        /// </summary>
        /// <returns>
        /// The amount of memory, in bytes, allocated for the associated process that cannot be shared with other processes.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property.</exception><filterpriority>2</filterpriority>
        public long PrivateMemorySize64
        {
            get { return _process.PrivateMemorySize64; }
        }

        /// <summary>
        /// Gets the privileged processor time for this process.
        /// </summary>
        /// <returns>
        /// A <see cref="T:System.TimeSpan"/> that indicates the amount of time that the process has spent running code inside the operating system core.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property. </exception><exception cref="T:System.NotSupportedException">You are attempting to access the <see cref="P:System.Diagnostics.Process.PrivilegedProcessorTime"/> property for a process that is running on a remote computer. This property is available only for processes that are running on the local computer. </exception><filterpriority>2</filterpriority>
        public TimeSpan PrivilegedProcessorTime
        {
            get { return _process.PrivilegedProcessorTime; }
        }

        /// <summary>
        /// Gets the name of the process.
        /// </summary>
        /// <returns>
        /// The name that the system uses to identify the process to the user.
        /// </returns>
        /// <exception cref="T:System.InvalidOperationException">The process does not have an identifier, or no process is associated with the <see cref="T:System.Diagnostics.Process"/>.-or- The associated process has exited. </exception><exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me); set <see cref="P:System.Diagnostics.ProcessStartInfo.UseShellExecute"/> to false to access this property on Windows 98 and Windows Me.</exception><exception cref="T:System.NotSupportedException">The process is not on this computer.</exception><filterpriority>1</filterpriority>
        public string ProcessName
        {
            get { return _process.ProcessName; }
        }

        /// <summary>
        /// Gets or sets the processors on which the threads in this process can be scheduled to run.
        /// </summary>
        /// <returns>
        /// A bitmask representing the processors that the threads in the associated process can run on. The default depends on the number of processors on the computer. The default value is 2 n -1, where n is the number of processors.
        /// </returns>
        /// <exception cref="T:System.ComponentModel.Win32Exception"><see cref="P:System.Diagnostics.Process.ProcessorAffinity"/> information could not be set or retrieved from the associated process resource.-or- The process identifier or process handle is zero. (The process has not been started.) </exception><exception cref="T:System.NotSupportedException">You are attempting to access the <see cref="P:System.Diagnostics.Process.ProcessorAffinity"/> property for a process that is running on a remote computer. This property is available only for processes that are running on the local computer. </exception><exception cref="T:System.InvalidOperationException">The process <see cref="P:System.Diagnostics.Process.Id"/> was not available.-or- The process has exited. </exception><filterpriority>2</filterpriority>
        public IntPtr ProcessorAffinity
        {
            get { return _process.ProcessorAffinity; }
            set { _process.ProcessorAffinity = value; }
        }

        /// <summary>
        /// Gets a value indicating whether the user interface of the process is responding.
        /// </summary>
        /// <returns>
        /// true if the user interface of the associated process is responding to the system; otherwise, false.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me); set <see cref="P:System.Diagnostics.ProcessStartInfo.UseShellExecute"/> to false to access this property on Windows 98 and Windows Me.</exception><exception cref="T:System.InvalidOperationException">There is no process associated with this <see cref="T:System.Diagnostics.Process"/> object. </exception><exception cref="T:System.NotSupportedException">You are attempting to access the <see cref="P:System.Diagnostics.Process.Responding"/> property for a process that is running on a remote computer. This property is available only for processes that are running on the local computer. </exception><filterpriority>1</filterpriority>
        public bool Responding
        {
            get { return _process.Responding; }
        }

        /// <summary>
        /// Gets the Terminal Services session identifier for the associated process.
        /// </summary>
        /// <returns>
        /// The Terminal Services session identifier for the associated process.
        /// </returns>
        /// <exception cref="T:System.NullReferenceException">There is no session associated with this process.</exception><exception cref="T:System.InvalidOperationException">There is no process associated with this session identifier.-or-The associated process is not on this machine. </exception><exception cref="T:System.PlatformNotSupportedException">The <see cref="P:System.Diagnostics.Process.SessionId"/> property is not supported on Windows 98.</exception><filterpriority>1</filterpriority>
        public int SessionId
        {
            get { return _process.SessionId; }
        }

        /// <summary>
        /// Gets or sets the properties to pass to the <see cref="M:System.Diagnostics.Process.Start"/> method of the <see cref="T:System.Diagnostics.Process"/>.
        /// </summary>
        /// <returns>
        /// The <see cref="T:System.Diagnostics.ProcessStartInfo"/> that represents the data with which to start the process. These arguments include the name of the executable file or document used to start the process.
        /// </returns>
        /// <exception cref="T:System.ArgumentNullException">The value that specifies the <see cref="P:System.Diagnostics.Process.StartInfo"/> is null. </exception><filterpriority>1</filterpriority>
        public ProcessStartInfo StartInfo
        {
            get { return _process.StartInfo; }
            set { _process.StartInfo = value; }
        }

        /// <summary>
        /// Gets the time that the associated process was started.
        /// </summary>
        /// <returns>
        /// A <see cref="T:System.DateTime"/> that indicates when the process started. This only has meaning for started processes.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property. </exception><exception cref="T:System.NotSupportedException">You are attempting to access the <see cref="P:System.Diagnostics.Process.StartTime"/> property for a process that is running on a remote computer. This property is available only for processes that are running on the local computer. </exception><exception cref="T:System.InvalidOperationException">The process has exited.</exception><exception cref="T:System.ComponentModel.Win32Exception">An error occurred in the call to the Windows function.</exception><filterpriority>1</filterpriority>
        public DateTime StartTime
        {
            get { return _process.StartTime; }
        }

        /// <summary>
        /// Gets or sets the object used to marshal the event handler calls that are issued as a result of a process exit event.
        /// </summary>
        /// <returns>
        /// The <see cref="T:System.ComponentModel.ISynchronizeInvoke"/> used to marshal event handler calls that are issued as a result of an <see cref="E:System.Diagnostics.Process.Exited"/> event on the process.
        /// </returns>
        /// <filterpriority>2</filterpriority>
        public ISynchronizeInvoke SynchronizingObject
        {
            get { return _process.SynchronizingObject; }
            set { _process.SynchronizingObject = value; }
        }

        /// <summary>
        /// Gets the set of threads that are running in the associated process.
        /// </summary>
        /// <returns>
        /// An array of type <see cref="T:System.Diagnostics.ProcessThread"/> representing the operating system threads currently running in the associated process.
        /// </returns>
        /// <exception cref="T:System.SystemException">The process does not have an <see cref="P:System.Diagnostics.Process.Id"/>, or no process is associated with the <see cref="T:System.Diagnostics.Process"/> instance.-or- The associated process has exited. </exception><exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me); set <see cref="P:System.Diagnostics.ProcessStartInfo.UseShellExecute"/> to false to access this property on Windows 98 and Windows Me.</exception><filterpriority>1</filterpriority>
        public ProcessThreadCollection Threads
        {
            get { return _process.Threads; }
        }

        /// <summary>
        /// Gets the total processor time for this process.
        /// </summary>
        /// <returns>
        /// A <see cref="T:System.TimeSpan"/> that indicates the amount of time that the associated process has spent utilizing the CPU. This value is the sum of the <see cref="P:System.Diagnostics.Process.UserProcessorTime"/> and the <see cref="P:System.Diagnostics.Process.PrivilegedProcessorTime"/>.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property. </exception><exception cref="T:System.NotSupportedException">You are attempting to access the <see cref="P:System.Diagnostics.Process.TotalProcessorTime"/> property for a process that is running on a remote computer. This property is available only for processes that are running on the local computer. </exception><filterpriority>2</filterpriority>
        public TimeSpan TotalProcessorTime
        {
            get { return _process.TotalProcessorTime; }
        }

        /// <summary>
        /// Gets the user processor time for this process.
        /// </summary>
        /// <returns>
        /// A <see cref="T:System.TimeSpan"/> that indicates the amount of time that the associated process has spent running code inside the application portion of the process (not inside the operating system core).
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property. </exception><exception cref="T:System.NotSupportedException">You are attempting to access the <see cref="P:System.Diagnostics.Process.UserProcessorTime"/> property for a process that is running on a remote computer. This property is available only for processes that are running on the local computer. </exception><filterpriority>2</filterpriority>
        public TimeSpan UserProcessorTime
        {
            get { return _process.UserProcessorTime; }
        }

        /// <summary>
        /// Gets the size of the process's virtual memory.
        /// </summary>
        /// <returns>
        /// The amount of virtual memory, in bytes, that the associated process has requested.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property. </exception><filterpriority>2</filterpriority>
        public int VirtualMemorySize
        {
            get { return _process.VirtualMemorySize; }
        }

        /// <summary>
        /// Gets the amount of the virtual memory allocated for the associated process.
        /// </summary>
        /// <returns>
        /// The amount of virtual memory, in bytes, allocated for the associated process.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property.</exception><filterpriority>2</filterpriority>
        public long VirtualMemorySize64
        {
            get { return _process.VirtualMemorySize64; }
        }

        /// <summary>
        /// Gets or sets whether the <see cref="E:System.Diagnostics.Process.Exited"/> event should be raised when the process terminates.
        /// </summary>
        /// <returns>
        /// true if the <see cref="E:System.Diagnostics.Process.Exited"/> event should be raised when the associated process is terminated (through either an exit or a call to <see cref="M:System.Diagnostics.Process.Kill"/>); otherwise, false. The default is false.
        /// </returns>
        /// <filterpriority>2</filterpriority>
        public bool EnableRaisingEvents
        {
            get { return _process.EnableRaisingEvents; }
            set { _process.EnableRaisingEvents = value; }
        }

        /// <summary>
        /// Gets a stream used to write the input of the application.
        /// </summary>
        /// <returns>
        /// A <see cref="T:System.IO.StreamWriter"/> that can be used to write the standard input stream of the application.
        /// </returns>
        /// <exception cref="T:System.InvalidOperationException">The <see cref="P:System.Diagnostics.Process.StandardInput"/> stream has not been defined because <see cref="P:System.Diagnostics.ProcessStartInfo.RedirectStandardInput"/> is set to false. </exception><filterpriority>1</filterpriority>
        public StreamWriter StandardInput
        {
            get { return _process.StandardInput; }
        }

        /// <summary>
        /// Gets a stream used to read the output of the application.
        /// </summary>
        /// <returns>
        /// A <see cref="T:System.IO.StreamReader"/> that can be used to read the standard output stream of the application.
        /// </returns>
        /// <exception cref="T:System.InvalidOperationException">The <see cref="P:System.Diagnostics.Process.StandardOutput"/> stream has not been defined for redirection; ensure <see cref="P:System.Diagnostics.ProcessStartInfo.RedirectStandardOutput"/> is set to true and <see cref="P:System.Diagnostics.ProcessStartInfo.UseShellExecute"/> is set to false.- or - The <see cref="P:System.Diagnostics.Process.StandardOutput"/> stream has been opened for asynchronous read operations with <see cref="M:System.Diagnostics.Process.BeginOutputReadLine"/>. </exception><filterpriority>1</filterpriority>
#if DEBUG
        private StreamReader _stdout = null;
#endif
        public StreamReader StandardOutput
        {
            get
            {
#if DEBUG
                if (_stdout == null)
                    _stdout = new StreamReader(new MemoryStream(ASCIIEncoding.ASCII.GetBytes(_command.Result)));
                return _stdout;
#endif
                return _process.StandardOutput;
            }
        }

#if DEBUG
        private StreamReader _stderr = null;
#endif

        /// <summary>
        /// Gets a stream used to read the error output of the application.
        /// </summary>
        /// <returns>
        /// A <see cref="T:System.IO.StreamReader"/> that can be used to read the standard error stream of the application.
        /// </returns>
        /// <exception cref="T:System.InvalidOperationException">The <see cref="P:System.Diagnostics.Process.StandardError"/> stream has not been defined for redirection; ensure <see cref="P:System.Diagnostics.ProcessStartInfo.RedirectStandardError"/> is set to true and <see cref="P:System.Diagnostics.ProcessStartInfo.UseShellExecute"/> is set to false.- or - The <see cref="P:System.Diagnostics.Process.StandardError"/> stream has been opened for asynchronous read operations with <see cref="M:System.Diagnostics.Process.BeginErrorReadLine"/>. </exception><filterpriority>1</filterpriority>
        public StreamReader StandardError
        {
            get
            {
#if DEBUG
                if (_stderr == null)
                    _stderr = new StreamReader(new MemoryStream(ASCIIEncoding.ASCII.GetBytes(_command.Error)));
                return _stderr;
#endif
                return _process.StandardError;
            }
        }

        /// <summary>
        /// Gets the associated process's physical memory usage.
        /// </summary>
        /// <returns>
        /// The total amount of physical memory the associated process is using, in bytes.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property. </exception><filterpriority>2</filterpriority>
        public int WorkingSet
        {
            get { return _process.WorkingSet; }
        }

        /// <summary>
        /// Gets the amount of physical memory allocated for the associated process.
        /// </summary>
        /// <returns>
        /// The amount of physical memory, in bytes, allocated for the associated process.
        /// </returns>
        /// <exception cref="T:System.PlatformNotSupportedException">The platform is Windows 98 or Windows Millennium Edition (Windows Me), which does not support this property.</exception><filterpriority>2</filterpriority>
        public long WorkingSet64
        {
            get { return _process.WorkingSet64; }
        }

        public event DataReceivedEventHandler OutputDataReceived
        {
            add { _process.OutputDataReceived += value; }
            remove { _process.OutputDataReceived -= value; }
        }

        public event DataReceivedEventHandler ErrorDataReceived
        {
            add { _process.ErrorDataReceived += value; }
            remove { _process.ErrorDataReceived -= value; }
        }

        public event EventHandler Exited
        {
            add { _process.Exited += value; }
            remove { _process.Exited -= value; }
        }
    }
}
