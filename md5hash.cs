// v1.0.0 - first release

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace md5hash {
	class md5hash {
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

		enum Mode { None, Read, Generate, Verify, Attach, Detach };

		static string target = "";
		static Mode opmode = Mode.None;
		static long minsize = 0, maxsize = long.MaxValue;
		static byte[] hash;
		static string hashString;

		public static void TextFgColor(System.ConsoleColor color) {
			System.Console.ForegroundColor = color;
		}

		public static void TextBgColor(System.ConsoleColor color) {
			System.Console.BackgroundColor = color;
		}

		static void CleanExit() {
			System.Console.ResetColor();
			Console.OutputEncoding = System.Text.Encoding.Default;
			Environment.Exit(1);
		}

		static void CalculateMD5(string filename) {
			string fullpath = Path.GetFullPath(filename);

			try {
				using (var md5 = MD5.Create()) {
					using (var stream = File.OpenRead(filename)) {
						hash = md5.ComputeHash(stream);
						hashString = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
					}
				}
			} catch (IOException ex) {
				TextFgColor(ConsoleColor.Red);
				Console.WriteLine(fullpath + "\t" + ex.Message);
				CleanExit();
			}
		}

		static void md5Read(string filename) {
			hash = new byte[16];
			uint bytesread = 0;
			uint handle = 0;
			string fullpath = Path.GetFullPath(filename);

			try {
				handle = CreateFileW(filename + ":md5", GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
			} catch (Exception ex) {
				TextFgColor(ConsoleColor.Red);
				Console.WriteLine(fullpath + "\t" + ex.Message);
				CleanExit();
			}
			if (handle == 0xFFFFFFFF) {
				TextFgColor(ConsoleColor.Yellow);
				Console.WriteLine(fullpath + "\tNo MD5");
				CleanExit();
			}
			ReadFile(handle, hash, 16, out bytesread, IntPtr.Zero);
			hashString = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
			TextFgColor(ConsoleColor.Green);
			Console.WriteLine(fullpath + "\tAttached MD5\t" + hashString);
			CloseHandle(handle);
		}

		static void md5Generate(string filename) {
			string fullpath = Path.GetFullPath(filename);

			CalculateMD5(filename);
			TextFgColor(ConsoleColor.Green);
			Console.WriteLine(fullpath + "\tGen MD5\t" + hashString);
		}

		static void md5Verify(string filename) {
			byte[] storedhash = new byte[16];
			string storedHashString;
			uint bytesread = 0;
			uint handle = 0;

			string fullpath = Path.GetFullPath(filename);
			try {
				handle = CreateFileW(filename + ":md5", GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
			} catch (Exception ex) {
				TextFgColor(ConsoleColor.Red);
				Console.WriteLine(fullpath + "\t" + ex.Message);
				CleanExit();
			}
			if (handle == 0xffffffff) {
				TextFgColor(ConsoleColor.Yellow);
				Console.WriteLine(fullpath + "\tNo MD5");
				CleanExit();
			}
			ReadFile(handle, storedhash, 16, out bytesread, IntPtr.Zero);
			storedHashString = BitConverter.ToString(storedhash).Replace("-", "").ToLowerInvariant();
			CloseHandle(handle);
			CalculateMD5(filename);
			if (storedHashString == hashString) {
				TextFgColor(ConsoleColor.Green);
				Console.WriteLine(fullpath + "\tMatch MD5\t" + hashString);
			} else {
				TextFgColor(ConsoleColor.Yellow);
				Console.WriteLine(fullpath + "\tMismatched MD5\t" + hashString + "\t" + storedHashString);
			}
		}

		static void md5Attach(string filename) {
			uint byteswritten = 0;
			uint handle = 0;

			string fullpath = Path.GetFullPath(filename);
			try {
				handle = CreateFileW(filename + ":md5", GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
			} catch (Exception ex) {
				TextFgColor(ConsoleColor.Red);
				Console.WriteLine(fullpath + "\t" + ex.Message);
				CleanExit();
			}
			if (handle != 0xFFFFFFFF) {
				TextFgColor(ConsoleColor.Yellow);
				Console.WriteLine(fullpath + "\tExisting MD5");
				CleanExit();
			}
			CalculateMD5(filename);
			TextFgColor(ConsoleColor.Green);
			Console.WriteLine(filename + "\tAttach MD5\t" + hashString);
			try {
				handle = CreateFileW(filename + ":md5", GENERIC_WRITE, FILE_SHARE_WRITE, IntPtr.Zero, OPEN_ALWAYS, 0, IntPtr.Zero);
			} catch (Exception ex) {
				TextFgColor(ConsoleColor.Red);
				Console.WriteLine(fullpath + "\t" + ex.Message);
				CleanExit();
			}
			WriteFile(handle, hash, 16, out byteswritten, IntPtr.Zero);
			CloseHandle(handle);
		}

		static void md5Detach(string filename) {
			string fullpath = Path.GetFullPath(filename);

			try {
				DeleteFileW(filename + ":md5");
			} catch (Exception ex) {
				TextFgColor(ConsoleColor.Red);
				Console.WriteLine(fullpath + "\t" + ex.Message);
				CleanExit();
			}
			TextFgColor(ConsoleColor.Green);
			Console.WriteLine(fullpath + "\tDetach MD5\t");
		}

		static void PrintHelp() {
			Console.WriteLine("md5hash v1.0 - (C)2018 Y0tsuya");
			Console.WriteLine("md5hash -[mode] -target [file] -min [size] -max [size]");
			Console.WriteLine("\tmodes:");
			Console.WriteLine("\t-read: read md5 stream");
			Console.WriteLine("\t-generate: generate and print md5 checksum");
			Console.WriteLine("\t-verify: generate md5 and verify against attached checksum");
			Console.WriteLine("\t-attach: generate md5 and attach it to the target");
			Console.WriteLine("\t-detach: detach md5 checksum from the target");
		}

		static void Main(string[] args) {
			int c;

			if (args.Length == 0) {
				PrintHelp();
				CleanExit();
			}

			Console.OutputEncoding = System.Text.Encoding.Unicode;
			for (c = 0 ; c < args.Length ; c++) {
				if (args[c] == "-read") {
					opmode = Mode.Read;
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
					minsize = Convert.ToInt64(args[c + 1]);
					c++;
				} else if (args[c] == "-max") {
					maxsize = Convert.ToInt64(args[c + 1]);
					c++;
				}
			}

			if (opmode == Mode.None) {
				TextFgColor(ConsoleColor.Red);
				Console.WriteLine("No opmode specified");
				CleanExit();
			}
			if (target == "") {
				TextFgColor(ConsoleColor.Red);
				Console.WriteLine("No target file specified");
				CleanExit();
			}

			FileInfo fi = new FileInfo(target);

			if (fi.Length < minsize) {
				TextFgColor(ConsoleColor.Yellow);
				Console.WriteLine(target + "\tunder minimum size " + minsize + " bytes");
				CleanExit();
			}

			if (fi.Length > maxsize) {
				TextFgColor(ConsoleColor.Yellow);
				Console.WriteLine(target + "\tover maximum size " + maxsize + " bytes");
				CleanExit();
			}

			switch (opmode) {
				case Mode.Read:
					md5Read(target);
					break;
				case Mode.Generate:
					md5Generate(target);
					break;
				case Mode.Verify:
					md5Verify(target);
					break;
				case Mode.Attach:
					md5Attach(target);
					break;
				case Mode.Detach:
					md5Detach(target);
					break;
				default: break;
			}

			System.Console.ResetColor();
		}
	}
}
