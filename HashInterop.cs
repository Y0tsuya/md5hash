using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CustomLibs {
	public class HashInterop {
		[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
		static extern uint CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr SecurityFileAttributes, uint dwCreationDisposition, uint dwFlagAndAttributes, IntPtr hTemplateFile);
		[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
		static extern bool DeleteFileW(string lpFileName);
		[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
		static extern bool CloseHandle(uint handle);
		[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
		static extern bool ReadFile(uint hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);
		[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
		static extern int WriteFile(uint hFile, [In] byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

		public const uint GENERIC_ALL = 0x10000000;
		public const uint GENERIC_EXECUTE = 0x20000000;
		public const uint GENERIC_WRITE = 0x40000000;
		public const uint GENERIC_READ = 0x80000000;
		public const uint FILE_SHARE_READ = 0x00000001;
		public const uint FILE_SHARE_WRITE = 0x00000002;
		public const uint FILE_SHARE_DELETE = 0x00000004;
		public const uint CREATE_NEW = 1;
		public const uint CREATE_ALWAYS = 2;
		public const uint OPEN_EXISTING = 3;
		public const uint OPEN_ALWAYS = 4;
		public const uint TRUNCATE_EXISTING = 5;
		public const int FILE_ATTRIBUTE_NORMAL = 0x80;

		public Func<int, string, int, int, int> LogCallBack;

		public string ErrorMessage;

		public enum HashFunctionType { MD5, SHA1, SHA256 };
		private string AdsExtension;
		private uint HashLen;
		private HashFunctionType Engine;
		private Stopwatch MyStopWatch;
		public TimeSpan Elapsed;

		public HashInterop() {
			LogCallBack = null;
			HashFunction = HashFunctionType.MD5;
			MyStopWatch = new Stopwatch();
		}

		public HashFunctionType HashFunction {
			set {
				Engine = value;
				switch (value) {
					case HashFunctionType.MD5:
						AdsExtension = ":md5";
						HashLen = 16;
						break;
					case HashFunctionType.SHA1:
						AdsExtension = ":sha1";
						HashLen = 20;
						break;
					case HashFunctionType.SHA256:
						AdsExtension = ":sha256";
						HashLen = 32;
						break;
				}
			}
		}

		public string GetHashString(byte[] hash) {
			if (hash == null) return "";
			return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
		}

		public byte[] Generate(string filename, bool logErr = false) {
			byte[] hash;
			filename = @"\\?\" + filename;

			MyStopWatch.Restart();
			try {
				switch (Engine) {
					case HashFunctionType.MD5:
						using (var md5 = MD5.Create()) {
							using (var stream = File.OpenRead(filename)) {
								hash = md5.ComputeHash(stream);
							}
						}
						break;
					case HashFunctionType.SHA1:
						using (var sha1 = SHA1.Create()) {
							using (var stream = File.OpenRead(filename)) {
								hash = sha1.ComputeHash(stream);
							}
						}
						break;
					case HashFunctionType.SHA256:
						using (var sha256 = SHA256.Create()) {
							using (var stream = File.OpenRead(filename)) {
								hash = sha256.ComputeHash(stream);
							}
						}
						break;
					default:
						hash = null;
						break;
				}
			} catch (IOException ex) {
				if ((LogCallBack != null) && logErr) LogCallBack(CallBacks.LOG_ADD, "HashInterop Error:" + ex.Message, CallBacks.LOG_ERROR, 0);
				ErrorMessage = ex.Message;
				hash = null;
			}
			MyStopWatch.Stop();
			Elapsed = MyStopWatch.Elapsed;
			return hash;
		}

		public bool Exist(string filename, bool logErr = false) {
			uint handle = 0;
			filename = @"\\?\" + filename;

			try {
				handle = CreateFileW(filename + AdsExtension, GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
			} catch (Exception ex) {
				if ((LogCallBack != null) && logErr) LogCallBack(CallBacks.LOG_ADD, "HashInterop Error:" + ex.Message, CallBacks.LOG_ERROR, 0);
				ErrorMessage = ex.Message;
				return false;
			}
			if (handle != 0xFFFFFFFF) {
				CloseHandle(handle);
				return true;
			} else {
				return false;
			}
		}

		public byte[] Read(string filename, bool logErr = false) {
			byte[] hash = new byte[HashLen];
			uint bytesread = 0;
			uint handle = 0;
			filename = @"\\?\" + filename;

			try {
				handle = CreateFileW(filename + AdsExtension, GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
			} catch (Exception ex) {
				if ((LogCallBack != null) && logErr) LogCallBack(CallBacks.LOG_ADD, "HashInterop Error:" + ex.Message, CallBacks.LOG_ERROR, 0);
				ErrorMessage = ex.Message;
				return null;
			}
			if (handle == 0xFFFFFFFF) { // no Hash
				if ((LogCallBack != null) && logErr) LogCallBack(CallBacks.LOG_ADD, "HashInterop Warning: No " + Engine.ToString() + " present", CallBacks.LOG_WARNING, 0);
				ErrorMessage = "No " + Engine.ToString() + " present";
				return null;
			}
			ReadFile(handle, hash, HashLen, out bytesread, IntPtr.Zero);
			CloseHandle(handle);
			return hash;
		}

		public bool Verify(string filename, bool logErr = false) {
			byte[] storedhash = new byte[HashLen];
			byte[] genhash;
			uint bytesread = 0;
			uint handle = 0;
			filename = @"\\?\" + filename;

			try {
				handle = CreateFileW(filename + AdsExtension, GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
			} catch (Exception ex) {
				if ((LogCallBack != null) && logErr) LogCallBack(CallBacks.LOG_ADD, "HashInterop Error:" + ex.Message, CallBacks.LOG_ERROR, 0);
				ErrorMessage = ex.Message;
				return false;
			}
			if (handle == 0xffffffff) { // no Hash
				if ((LogCallBack != null) && logErr) LogCallBack(CallBacks.LOG_ADD, "HashInterop Warning: No " + Engine.ToString() + " present", CallBacks.LOG_WARNING, 0);
				ErrorMessage = "No " + Engine.ToString() + " present";
				return false;
			}
			ReadFile(handle, storedhash, HashLen, out bytesread, IntPtr.Zero);
			CloseHandle(handle);
			genhash = Generate(filename);
			if (genhash.SequenceEqual(storedhash)) return true;
			else return false;
		}

		public bool Attach(string filename, bool logErr = false) {
			uint handle = 0;
			byte[] genhash;
			filename = @"\\?\" + filename;

			try {
				handle = CreateFileW(filename + AdsExtension, GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
			} catch (Exception ex) {
				if ((LogCallBack != null) && logErr) LogCallBack(CallBacks.LOG_ADD, "HashInterop Error:" + ex.Message, CallBacks.LOG_ERROR, 0);
				ErrorMessage = ex.Message;
				return false;
			}
			if (handle != 0xFFFFFFFF) { // existing hash
				if ((LogCallBack != null) && logErr) LogCallBack(CallBacks.LOG_ADD, "HashInterop Alert: Existing " + Engine.ToString(), CallBacks.LOG_ALERT, 0);
				ErrorMessage = "Existing " + Engine.ToString();
				return false;
			}
			genhash = Generate(filename);
			return Attach(filename, genhash);
		}

		public bool Attach(string filename, byte[] hash, bool logErr = false) {
			uint byteswritten = 0;
			uint handle = 0;
			DateTime modify;
			filename = @"\\?\" + filename;

			modify = File.GetLastWriteTime(filename);

			try {
				handle = CreateFileW(filename + AdsExtension, GENERIC_WRITE, FILE_SHARE_WRITE, IntPtr.Zero, OPEN_ALWAYS, 0, IntPtr.Zero);
			} catch (Exception ex) {
				if ((LogCallBack != null) && logErr) LogCallBack(CallBacks.LOG_ADD, "HashInterop Error:" + ex.Message, CallBacks.LOG_ERROR, 0);
				ErrorMessage = ex.Message;
				return false;
			}
			if (handle == 0xffffffff) { // no file handle
				if ((LogCallBack != null) && logErr) LogCallBack(CallBacks.LOG_ADD, "HashInterop Alert: Invalid ADS file hanel", CallBacks.LOG_ALERT, 0);
				//if ((LogCallBack != null) && logErr) LogCallBack(CallBacks.LOG_ADD, filename, CallBacks.LOG_ALERT, 0);
				return false;
			}
			WriteFile(handle, hash, HashLen, out byteswritten, IntPtr.Zero);
			//if ((LogCallBack != null) && logErr) LogCallBack(CallBacks.LOG_ADD, String.Format("HashInterop Debug: Handle {0:X} {1} bytes written", handle, byteswritten), CallBacks.LOG_INFO, 0);
			CloseHandle(handle);
			File.SetLastWriteTime(filename, modify);
			if (byteswritten == HashLen) {
				return true;
			} else {
				if ((LogCallBack != null) && logErr) LogCallBack(CallBacks.LOG_ADD, String.Format("HashInterop Error: {0}-byte {1} Write Failure", HashLen, Engine.ToString()), CallBacks.LOG_ERROR, 0);
				return false;
			}
		}

		public bool Detach(string filename, bool logErr = false) {
			filename = @"\\?\" + filename;
			try {
				DeleteFileW(filename + AdsExtension);
			} catch (Exception ex) {
				if ((LogCallBack != null) && logErr) LogCallBack(CallBacks.LOG_ADD, "HashInterop Error:" + ex.Message, CallBacks.LOG_ERROR, 0);
				ErrorMessage = ex.Message;
				return false;
			}
			return true;
		}
	}
}