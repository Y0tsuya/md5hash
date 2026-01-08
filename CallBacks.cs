using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CustomLibs {

	public class CallBacks {
		// int: optype: LOG_ADD,LOG_SUB,LOG_UPD
		// string: msg,
		// int: LOG_INFO,LOG_ALERT, LOG_WARNING,LOG_ERROR
		// int: subindex,
		// return int (current index)
		// index = LogcallBack(optype, message, errorlevel, subindex);
		//public Func<int, string, int, int, int> LogCallBack;
		// int: max (0/-1 = no set), progress (-1 = no set)
		//public Action<int, int> ProgressCallBack;
		//public Action DoEvents;
		public const int LOG_ADD = 0;
		public const int LOG_SUB = 1;
		public const int LOG_UPD = 2;
		public const int LOG_INFO = 0;
		public const int LOG_ALERT = 1;
		public const int LOG_WARNING = 2;
		public const int LOG_ERROR = 3;
	}
}
