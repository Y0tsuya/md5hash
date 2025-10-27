using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Reflection;
using CustomLibs;

// v1.0.0	first release
// v1.0.1	improved Printhelp()
//			fix FilInfo.Length file not found
// v1.0.2	by default ignore soft links
// v1.0.3	attach mode wasn't using fullpath
// v1.0.4	if file not found, pause for 100 ms then try again
// v1.0.5	preserve modify time after attachment
// v1.0.6	Switch to AlphaFS
// v1.0.7	Decode/Encode size units
// v1.0.8	output encoding adjustment
// v1.0.9	Add verbose
// v1.1.0	Refactor Console.WriteLine
// v2.0.0	Migrate to .NET 6
//			Integrate HashInterop
// v2.0.1	Fix attach operation generating 0000000 MD5
// v2.0.2	Skip already attached hashes

namespace md5hash {
	class md5hash {

		enum Mode { None, Read, Generate, Verify, Attach, Detach };

		public static void TextFgColor(System.ConsoleColor color) {
			System.Console.ForegroundColor = color;
		}

		public static void TextBgColor(System.ConsoleColor color) {
			System.Console.BackgroundColor = color;
		}

		static void Write(string text) {
			System.Console.Write(text);
		}

		static void Write(string text, System.ConsoleColor color) {
			System.Console.ForegroundColor = color;
			System.Console.Write(text);
		}

		static void WriteLine(string text) {
			System.Console.WriteLine(text);
		}

		static void WriteLine(string text, System.ConsoleColor color) {
			System.Console.ForegroundColor = color;
			System.Console.WriteLine(text);
		}

		static void CleanExit() {
			System.Console.ResetColor();
			//			Console.OutputEncoding = System.Text.Encoding.Default;
			Environment.Exit(1);
		}

		public const int LOG_ADD = 0;
		public const int LOG_SUB = 1;
		public const int LOG_UPD = 2;
		public const int LOG_INFO = 0;
		public const int LOG_ALERT = 1;
		public const int LOG_WARNING = 2;
		public const int LOG_ERROR = 3;
		static int LogCallBackHandler(int op, string msg, int errlvl, int subidx) {
			ConsoleColor clr = ConsoleColor.Gray;
			switch (errlvl) {
				case LOG_INFO: clr = ConsoleColor.DarkGreen; break;
				case LOG_ALERT: clr = ConsoleColor.DarkCyan; break;
				case LOG_WARNING: clr = ConsoleColor.DarkYellow; break;
				case LOG_ERROR: clr = ConsoleColor.Red; break;
			}
			WriteLine(msg, clr);
			return 0;
		}

		static void ProgressCallBackHandler(int max, int value) {
			if (max > 0) {
			}
			if (value >= 0) {
				Write(".");
			}
		}

		static void DoEventCallbackHandler() {
			//Write(".");
		}

		static void md5Read(HashInterop md5, string filename) {
			byte[] hash;
			string fullpath = Path.GetFullPath(filename);
			hash = md5.Read(fullpath, true);
			string hashString;

			if (hash != null) {
				hashString = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
				WriteLine(fullpath + "\tAttached MD5\t" + hashString, ConsoleColor.Green);
			}
		}

		static void md5Generate(HashInterop md5, string filename) {
			string fullpath = Path.GetFullPath(filename);
			byte[] hash;
			string hashString;

			hash = md5.Generate(filename);
			if (hash != null) {
				hashString = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
				WriteLine(fullpath + "\tGen MD5\t" + hashString, ConsoleColor.Green);
			}
		}

		static void md5Verify(HashInterop md5, string filename) {
			byte[] hash;
			string hashString;
			byte[] storedhash = new byte[16];
			string storedHashString = "";

			string fullpath = Path.GetFullPath(filename);

			storedhash = md5.Read(fullpath);
			hash = md5.Generate(fullpath);
			if (storedhash != null) {
				storedHashString = BitConverter.ToString(storedhash).Replace("-", "").ToLowerInvariant();
			} else {
				CleanExit();
			}
			hashString = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
			if (storedHashString == hashString) {
				WriteLine(fullpath + "\tMatch MD5\t" + hashString, ConsoleColor.Green);
			} else {
				WriteLine(fullpath + "\tMismatched MD5\t" + hashString + "\t" + storedHashString, ConsoleColor.Yellow);
			}
		}

		static void md5Attach(HashInterop md5, string filename) {
			DateTime modify;

			string fullpath = Path.GetFullPath(filename);
			modify = File.GetLastWriteTime(filename);
			byte[] hash;
			string hashString;
			bool success;

			if (md5.Exist(fullpath)) {
				WriteLine(fullpath + "\tMD5 Exists\t", ConsoleColor.DarkYellow);
				return;
			}
			hash = md5.Generate(fullpath, true);
			success = md5.Attach(fullpath, hash, true);
			if (success) {
				hashString = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
				WriteLine(fullpath + "\tAttach MD5\t" + hashString, ConsoleColor.Green);
				File.SetLastWriteTime(filename, modify);
			}
		}

		static void md5Detach(HashInterop md5, string filename) {
			string fullpath = Path.GetFullPath(filename);
			if (md5.Detach(fullpath, true)) {
				WriteLine(fullpath + "\tDetach MD5\t", ConsoleColor.Green);
			}
		}

		const int KB = 1024;
		const int MB = 1024 * 1024;
		const int GB = 1024 * 1024 * 1024;

		static long DecodeByteSize(string num) {
			long bytes;

			if (num.Substring(num.Length - 2) == "GB") {
				bytes = Convert.ToInt64(num.Substring(0, num.Length - 2)) * GB;
			} else if (num.Substring(num.Length - 2) == "MB") {
				bytes = Convert.ToInt64(num.Substring(0, num.Length - 2)) * MB;
			} else if (num.Substring(num.Length - 2) == "KB") {
				bytes = Convert.ToInt64(num.Substring(0, num.Length - 2)) * KB;
			} else {
				bytes = Convert.ToInt64(num);
			}
			return bytes;
		}

		static string EncodeByteSize(long num) {
			string si;
			double fp;

			if (num > GB) {
				fp = (double)num / (double)GB;
				si = String.Format("{0:F2}GB", fp);
			} else if (num > MB) {
				fp = (double)num / (double)MB;
				si = String.Format("{0:F2}MB", fp);
			} else if (num > KB) {
				fp = (double)num / (double)KB;
				si = String.Format("{0:F2}KB", fp);
			} else {
				si = String.Format("{0} Bytes", num);
			}

			return si;
		}

		static string ParseVersion() {
			Assembly execAssembly = Assembly.GetCallingAssembly();
			AssemblyName name = execAssembly.GetName();
			string ver = String.Format("{0}.{1}.{2}", name.Version.Major.ToString(), name.Version.Minor.ToString(), name.Version.Build.ToString());
			return ver;
		}

		static void PrintHelp() {
			WriteLine("md5hash v" + ParseVersion() + " - (C)2018-2024 Y0tsuya");
			WriteLine("md5hash -[mode] -target [file] -min [size] -max [size] -followlink");
			WriteLine("\tmodes:");
			WriteLine("\t-read: read attached md5 stream");
			WriteLine("\t-generate: generate and print md5 checksum");
			WriteLine("\t-verify: generate md5 and verify against attached checksum");
			WriteLine("\t-attach: generate md5 and attach it to the target");
			WriteLine("\t-detach: detach md5 checksum from the target");
			WriteLine("");
			WriteLine("\t-min: minimum file size to consider (in bytes), defaults to 0");
			WriteLine("\t-max: maximum file size to consider (in bytes), defaults to 64-bit max");
			WriteLine("\t-followlink: follow soft links");
			WriteLine("\t-verbose: print extra debug info");
		}

		static void Main(string[] args) {
			int c;
			FileInfo fi = null;
			string fullpath = "";
			string target = "";
			Mode opmode = Mode.None;
			long minsize = 0, maxsize = long.MaxValue;
			bool followlink = false;
			bool verbose;

			if (args.Length == 0) {
				PrintHelp();
				CleanExit();
			}

			verbose = false;
			Console.OutputEncoding = System.Text.Encoding.Unicode;
			for (c = 0; c < args.Length; c++) {
				if (args[c] == "-read") {
					opmode = Mode.Read;
				} else if (args[c] == "-verbose") {
					verbose = true;
				} else if (args[c] == "-generate") {
					opmode = Mode.Generate;
				} else if (args[c] == "-verify") {
					opmode = Mode.Verify;
				} else if (args[c] == "-attach") {
					opmode = Mode.Attach;
				} else if (args[c] == "-detach") {
					opmode = Mode.Detach;
				} else if (args[c] == "-target") {
					target = args[c + 1];
					c++;
				} else if (args[c] == "-min") {
					minsize = DecodeByteSize(args[c + 1]);
					c++;
				} else if (args[c] == "-max") {
					maxsize = DecodeByteSize(args[c + 1]);
					c++;
				}
			}

			if (opmode == Mode.None) {
				WriteLine("No opmode specified", ConsoleColor.Red);
				CleanExit();
			}
			if (target == "") {
				WriteLine("No target file specified", ConsoleColor.Red);
				CleanExit();
			}

			if (verbose) {
				TextFgColor(ConsoleColor.Cyan);
				WriteLine("Mode: " + opmode.ToString());
				WriteLine("Min: " + minsize);
				WriteLine("Max: " + maxsize);
				WriteLine("Target: " + target);
			}

			if (!File.Exists(target)) {
				System.Threading.Thread.Sleep(100);
				if (!File.Exists(target)) { // file really doesn't exist
					fullpath = Path.GetFullPath(target);
					WriteLine(fullpath + "\tNOT FOUND", ConsoleColor.Red);
					CleanExit();
				}
			}

			if ((File.GetAttributes(target) & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint) {
				if (!followlink) {
					fullpath = Path.GetFullPath(target);
					WriteLine(fullpath + "\tLINK", ConsoleColor.Yellow);
					CleanExit();
				}
			}

			try {
				fi = new FileInfo(target);
			} catch (IOException ex) {
				WriteLine(fullpath + "\t" + ex.Message, ConsoleColor.Red);
				CleanExit();
			}

			if (fi.Length < minsize) {
				WriteLine(target + "\tunder minimum size " + EncodeByteSize(minsize), ConsoleColor.Yellow);
				CleanExit();
			}

			if (fi.Length > maxsize) {
				WriteLine(target + "\tover maximum size " + EncodeByteSize(maxsize), ConsoleColor.Yellow);
				CleanExit();
			}

			HashInterop myMD5 = new HashInterop();
			myMD5.LogCallBack += LogCallBackHandler;

			switch (opmode) {
				case Mode.Read:
					md5Read(myMD5, target);
					break;
				case Mode.Generate:
					md5Generate(myMD5, target);
					break;
				case Mode.Verify:
					md5Verify(myMD5, target);
					break;
				case Mode.Attach:
					md5Attach(myMD5, target);
					break;
				case Mode.Detach:
					md5Detach(myMD5, target);
					break;
				default: break;
			}

			System.Console.ResetColor();
		}
	}
}
