using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Data;
using System.Linq;
using System.Data.SqlClient;
using SnmpSharpNet;

namespace UDPListener
{
	class SNMPTrapReceiver
	{

        public static string GenericName(int genericNum)
        {
            switch(genericNum)
            {
                case 0:
                    return "Cold start";
                case 1:
                    return "Warm start";
                case 2:
                    return "Link Down";
                case 3:
                    return "Link up";
                case 4:
                    return "Authentication failure";
                case 5:
                    return "Egp neighbor loss";
                default:
                    return "Enterprise specific";
            }
        }

        public static int CheckIgnore(string[] tables, SqlConnection conn, String Oid)
        {
			for (int i = 0; i < tables.Length; i++)
			{
				try
				{
					SqlDataReader myReader = null;
					SqlCommand myCommand = new SqlCommand("select * from " + tables[i],
															 conn);
					myReader = myCommand.ExecuteReader();
					while (myReader.Read())
					{
						string curr = myReader["Oid"].ToString();
                        int ignore = (int)myReader["Ignore"];
						if (Oid.StartsWith(curr, StringComparison.CurrentCulture))
						{
							return ignore;
						}
					}
				}
				catch (Exception e)
				{
					Console.WriteLine(e.ToString());
				}
			}
			return 0;   
        }

        public static bool ReadOidTables(string [] tables,SqlConnection conn,String Oid)
        {
            for (int i = 0; i < tables.Length; i++){
				try
				{
					SqlDataReader myReader = null;
					SqlCommand myCommand = new SqlCommand("select * from " + tables[i],
															 conn);
					myReader = myCommand.ExecuteReader();
					while (myReader.Read())
					{
                        string curr = myReader["Oid"].ToString();
                        if (Oid.StartsWith(curr,StringComparison.CurrentCulture)){
                            return true;
                        }
					}
				}
				catch (Exception e)
				{
					Console.WriteLine(e.ToString());
				}
            }
            return false;
        }

        public static string ReadMIBTables(string [] tables,SqlConnection conn,String enterprise_num){
			for (int i = 0; i < tables.Length; i++)
			{
				try
				{
					SqlDataReader myReader = null;
					SqlCommand myCommand = new SqlCommand("select * from " + tables[i],
															 conn);
					myReader = myCommand.ExecuteReader();
					while (myReader.Read())
					{
						string curr = myReader["Enterprise Number"].ToString();
                        if (curr.Equals(enterprise_num))
						{
                            return myReader["Enterprise Name"].ToString();
						}
					}
				}
				catch (Exception e)
				{
					Console.WriteLine(e.ToString());
				}
			}
            return "";
        }

	    public static void Main(string[] args)
		{
			// Construct a socket and bind it to the trap manager port 162 

			Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
			IPEndPoint ipep = new IPEndPoint(IPAddress.Any, 162);
			EndPoint ep = (EndPoint)ipep;
			socket.Bind(ep);
			// Disable timeout processing. Just block until packet is received 
			socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 0);
			bool run = true;
			int inlen = -1;
			while (run)
			{
				byte[] indata = new byte[16 * 1024];
				// 16KB receive buffer int inlen = 0;
				IPEndPoint peer = new IPEndPoint(IPAddress.Any, 0);
				EndPoint inep = (EndPoint)peer;
				try
				{
					inlen = socket.ReceiveFrom(indata, ref inep);
				}
				catch (Exception ex)
				{
					Console.WriteLine("Exception {0}", ex.Message);
					inlen = -1;
				}
				if (inlen > 0)
				{
                    using (SqlConnection conn = new SqlConnection())
                    {
                        conn.ConnectionString = "Server=ANDREW-PC\\SQLEXPRESS;Database=TestSNMPDatabase;Trusted_Connection=true;MultipleActiveResultSets=True";
						conn.Open();
                       
                        // Parse SNMP Version 1 TRAP packet 
                        SnmpV1TrapPacket pkt = new SnmpV1TrapPacket();
                        pkt.decode(indata, inlen);

                        Console.WriteLine("community=" + pkt.Community);
                        Console.WriteLine("enterprise=" + pkt.Pdu.Enterprise);
                        Console.WriteLine("enterprise_mib_name=");
                        Console.WriteLine("uptime=" + pkt.Pdu.TimeStamp.ToString());
                        Console.WriteLine("agent_ip=" + pkt.Pdu.AgentAddress.ToString());
                        Console.WriteLine("generic_num=" + pkt.Pdu.Generic);
                        Console.WriteLine("specific_num=" + pkt.Pdu.Specific);
                        Console.WriteLine("version=" + pkt.Version);
                        Console.WriteLine("generic_name=" + GenericName(pkt.Pdu.Generic));
                        Console.WriteLine("type=" + pkt.Pdu.Type);

                        string rawMessage = "";
                        string friendlyMessage = "";
                        List<string> messages = new List<string>();
                        List<string> friendlyMessageList = new List<string>();
                        string[] Oidtables = { "OidTable" };
                        string[] MIBtables = { "EnterpriseMibName" };
                        string enterprise_num = pkt.Pdu.Enterprise.ToString().Split('.')[6];
                        string mibName = ReadMIBTables(MIBtables, conn, enterprise_num);
                        bool first = true;
                        int ignoreVal = 0;

                        foreach (Vb v in pkt.Pdu.VbList)
                        {
                            int varValue = Int32.Parse(v.Oid.ToString().Split('.').Last());
                            Console.WriteLine("**** {0} {1}: {2}", v.Oid.ToString(), SnmpConstants.GetTypeName(v.Value.Type), v.Value.ToString());
                            messages.Add("var" + varValue.ToString("D2") + "_oid=" + v.Oid);
                            messages.Add("var" + varValue.ToString("D2") + "_value=" +  v.Value.ToString());
                            if (ReadOidTables(Oidtables,conn,v.Oid.ToString()))
                            {
                                friendlyMessageList.Add("var" + varValue.ToString("D2") + "_oid=" + v.Oid);
                                friendlyMessageList.Add("var" + varValue.ToString("D2") + "_value=" + v.Value.ToString());
                            }
                            //check first OID in ignore table
                            if (first){
                                ignoreVal = CheckIgnore(Oidtables, conn, v.Oid.ToString());
                                first = false;
                            }

                        }
                        rawMessage = string.Join(",", messages);
                        friendlyMessage = string.Join(",", friendlyMessageList);
                        Console.WriteLine("Friendly message: " + friendlyMessage);

						string sql = "INSERT INTO SNMPTable ([SNMP version],Community,[Enterprise OID],enterprise_mib_name," +
                                     "[Agent IP],[Generic Number],[Friendly Message],[Raw Message],Timestamp,Ignore) " +
									 "VALUES (@0, @1, @2, @3, @4, @5, @6, @7, @8, @9)"; 
						SqlCommand insertCommand = new SqlCommand(sql, conn);
                        int max = 8000; //max length of varchar in sql server
                        insertCommand.Parameters.Add("@0", SqlDbType.VarChar, max).Value = pkt.Version.ToString();
                        insertCommand.Parameters.Add("@1", SqlDbType.VarChar, max).Value = pkt.Community.ToString();
                        insertCommand.Parameters.Add("@2", SqlDbType.VarChar, max).Value = pkt.Pdu.Enterprise.ToString();
                        insertCommand.Parameters.Add("@3", SqlDbType.VarChar, max).Value = mibName;
                        insertCommand.Parameters.Add("@4", SqlDbType.VarChar, max).Value = pkt.Pdu.AgentAddress.ToString();
                        insertCommand.Parameters.Add("@5", SqlDbType.VarChar, max).Value = pkt.Pdu.Generic.ToString();
                        insertCommand.Parameters.Add("@6", SqlDbType.VarChar, max).Value = friendlyMessage;
                        insertCommand.Parameters.Add("@7", SqlDbType.VarChar, max).Value = rawMessage;
                        insertCommand.Parameters.Add("@8", SqlDbType.VarChar, max).Value = DateTime.Now.ToString("yyyyMMdd h:mm:ss tt");
                        insertCommand.Parameters.Add("@9", SqlDbType.Int).Value = ignoreVal;
						insertCommand.ExecuteNonQuery();
						conn.Close();
                        Console.WriteLine("** End of SNMP Version 1 TRAP data.");
                    }
				}
				else
				{
					if (inlen == 0)
						Console.WriteLine("Zero length packet received.");
				}
			}
		}
	}
}
