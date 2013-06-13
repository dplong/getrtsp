///
/// This file contains the top-level code for a simple RTSP/UDP client.

#include "stdafx.h"

#include <iomanip>
#include <vector>
#include <cassert>
#include <string>
#include <sstream>
#include <iostream>
#include <list>
#include <WinSock2.h> // Windows Sockets 2.0

#pragma comment(lib, "Ws2_32.lib")

using namespace std;

#pragma region Housekeeping

///
/// Require at least Winsock v1.1 (we're not doing anything fancy).
static const WORD WINSOCK_VERSION_REQUESTED = MAKEWORD(1, 1);

///
/// Maximum length of a local host name.
///
/// @note From MSDN: "So if a buffer of 256 bytes is passed in the name
/// parameter and the namelen parameter is set to 256, the buffer size will
/// always be adequate."
static const size_t LOCAL_HOST_NAME_MAXIMUM_LENGTH = (255);

///
/// Maximum size of buffer containing local host name.
///
/// @see LOCAL_HOST_NAME_MAXIMUM_LENGTH
static const size_t LOCAL_HOST_NAME_MAXIMUM_BUFFER_SIZE = (LOCAL_HOST_NAME_MAXIMUM_LENGTH + 1);

///
/// Character to use for packet-count-limit command-line option.
static const char COMMAND_LINE_OPTION_CHAR_COUNT = 'c';

///
/// Character to use for time-limit command-line option.
static const char COMMAND_LINE_OPTION_CHAR_TIME = 't';

///
/// Character to use for RTSP-path command-line option.
static const char COMMAND_LINE_OPTION_CHAR_PATH = 'p';

///
/// Character to use for verbosity command-line option.
static const char COMMAND_LINE_OPTION_CHAR_VERB = 'v';

///
/// Character to use for credentials command-line option.
static const char COMMAND_LINE_OPTION_CHAR_CRED = 'a';

///
/// Default RTSP TCP port on server (camera).
static const unsigned DEFAULT_RTSP_PORT = 554;

///
/// Default RTP UDP port on client (us).
static const unsigned DEFAULT_RTP_PORT = 6970;

///
/// Default packet limit.
///
/// @note 0 means unlimited.
static const unsigned DEFAULT_PACKET_LIMIT = 0;

///
/// Default RTSP-session time limit.
static const unsigned DEFAULT_TIME_LIMIT_SEC = 5;

///
/// Default RTSP URI path.
static const string DEFAULT_RTSP_PATH = "/media/video1";

enum VERB
{
  VERB_NONE = 0, // No console output at all.
	VERB_SUMMARY = 1, // Summary, after session completes.
	VERB_LIST = 2, // Summary and list of RTP-packet gaps.
	VERB_RTSP = 3, // Summary, list, and RTSP messages.
};

///
/// Default verbosity.
static const VERB DEFAULT_VERB = VERB_LIST;

///
/// Size of the MTU.
///
/// @note Although this can vary, it is virtually always 1500 for Ethernet v2.
static const size_t MAXIMUM_TRANSMISSION_UNIT_SIZE = 1500;

///
/// Whether we should read the entire RTP packet.
///
/// @note Comment out to disable (read only the absolute minimum). It is
/// recommended to leave this manifest constant commented out. Only uncomment
/// it if you are paranoid and think that we really should read in the entire
/// packet.
///
/// @note Normally, one would read the entire packet; however, we really only
/// need to look at the first few bytes in order to detect packet loss.
/// Therefore, comment this manifest constant out to force the code to read in
/// the first few bytes it actually needs. The idea is that saves a tiny amount
/// of processing power by avoiding unneccesary copying of memory.
// #define READ_ENTIRE_RTP_PACKET

///
/// Size of the buffer into which we read an RTP packet.
static const size_t RTP_PACKET_BUFFER_LENGTH = 
#ifdef READ_ENTIRE_RTP_PACKET
	MAXIMUM_TRANSMISSION_UNIT_SIZE
#else
	// Since we just need to inspect the RTP sequence number, which is
	// in the 3rd and 4th bytes, just read the first 4 bytes of each
	// packet. The IP stack returns the truncated packet--it discards
	// all of the packet after those first 4 bytes. We do this to
	// minimize the processing required to copy the entire packet to
	// our buffer.
	4
#endif
	;

///
/// Packet-loss snapshot.
struct PacketLoss {
	WORD previous; // Sequence number of previous RTP packet.
	WORD current; // Sequence number of RTP packet received after previous.
	UINT64 received; // Number of packets received so far.
	UINT64 lost; // Number of packets lost so far.
};

///
/// List of packet loss incidences.
typedef list<PacketLoss> PacketLossList;

///
/// Get last error for socket.
///
/// @param[in] socket Socket on which error occurred.
/// @return Socket error code.
static int GetLastSocketError(SOCKET socket)
{
	assert(socket != INVALID_SOCKET);

	int errorCode;
	int errorCodeSize = sizeof errorCode;
	getsockopt(socket, SOL_SOCKET, SO_ERROR,
		reinterpret_cast<char *>(&errorCode), &errorCodeSize);

	return errorCode;
}

///
/// Report socket error.
///
/// Write error text and socket's last error code to standard error stream.
///
/// @param[in] socket Socket on which error occurred.
/// @param[in] errorText Text describing socket error.
static void ReportSocketError(SOCKET socket, const string &errorText)
{
	assert(socket != INVALID_SOCKET);
	assert(!errorText.empty());

	ReportSocketError(GetLastSocketError(socket), errorText);
}

///
/// Report socket error.
///
/// Write error text and socket error code to standard error stream.
///
/// @param[in] errorCode Error code to report.
/// @param[in] errorText Text describing socket error.
static void ReportSocketError(int errorCode, const string &errorText)
{
	assert(!errorText.empty());

	if (errorCode != NO_ERROR)
	{
		cerr << "Error: " << errorText << " (error code " << errorCode << ")"
			<< endl;
	}
}

///
/// Get local host name and list of local IP addresses.
///
/// @param[out] hostName Local host name.
/// @param[out] ipAddresses List of local IP addresses in NIC order.
/// @return Whether could get at least one IP address.
static bool GetLocalIpAddresses(string &hostName, list<string> &ipAddresses)
{
	bool gotEm = false;

	char ac[LOCAL_HOST_NAME_MAXIMUM_BUFFER_SIZE];
    if (gethostname(ac, sizeof ac) == SOCKET_ERROR)
	{
        cerr << "Error: could not get local host name"
			<< " (error code " << WSAGetLastError() << ")" << endl;
	}
	else
	{
		hostName = ac;

		const struct hostent *phe = gethostbyname(ac);
		if (phe == NULL)
		{
			cerr << "Error: could not get information for host, " << ac
				<< " (error code " << WSAGetLastError() << ")" << endl;
		}
		else
		{
			ipAddresses.clear();

			for (unsigned i = 0; phe->h_addr_list[i] != NULL; ++i)
			{
				ipAddresses.push_back(inet_ntoa(
					*reinterpret_cast<struct in_addr *>(phe->h_addr_list[i])));
			}

			gotEm = !ipAddresses.empty();
		}
	}

	return gotEm;
}

///
/// Get IP address of this host's first NIC.
///
/// @param[out] ipAddress IP address in dot-decimal notation.
/// @return Whether got (first) local IP address.
static bool GetLocalIpAddress(string &ipAddress)
{
	ipAddress.clear();

	string hostName;
	list<string> ipAddresses;
	if (GetLocalIpAddresses(hostName, ipAddresses) &&
		!ipAddresses.empty()) // (Check, just to be safe)
	{
		ipAddress = ipAddresses.front();
	}

	return !ipAddress.empty();
}

///
/// Get positional arguments.
///
/// @param[in] positionals Positional arguments.
/// @param[out] remoteIpAddress IP address of remote server in dot-decimal notation.
/// @param[out] remotePort TCP port on which to connect; defaults to DEFAULT_RTSP_PORT.
/// @param[out] localPort UDP port on which to listen for RTP packets; defaults to DEFAULT_RTP_PORT.
/// @return Whether positional arguments are valid.
static bool GetPositionalArguments(const vector<string> &positionals,
	string &remoteIpAddress, unsigned &remotePort, unsigned &localPort)
{
	remoteIpAddress.clear();
	remotePort = 0;
	localPort = 0;

	if (positionals.size() >= 1)
	{
		if (inet_addr(positionals[0].c_str()) == INADDR_NONE)
		{
			cerr << "Error: invalid IP address (" << positionals[0] << ")"
				<< endl;
		}
		else
		{
			remoteIpAddress = positionals[0];

			if (positionals.size() >= 2)
			{
				remotePort = atoi(positionals[1].c_str());
				if (remotePort == 0)
				{
					cerr << "Error: invalid port number ("
						<< positionals[1] << ")" << endl;
				}
				else
				{
					if (positionals.size() >= 3)
					{
						localPort = atoi(positionals[2].c_str());
						if (localPort == 0)
						{
							cerr << "Error: invalid port number ("
								<< positionals[2] << ")" << endl;
						}
					}
					else
					{
						localPort = DEFAULT_RTP_PORT;
					}
				}
			}
			else
			{
				localPort = DEFAULT_RTP_PORT;
				remotePort = DEFAULT_RTSP_PORT;
			}
		}
	}

	return !remoteIpAddress.empty() && remotePort != 0 && localPort != 0;
}

///
/// Get command-line arguments.
///
/// @param[in] argc Argument count.
/// @param[in] argv Argument values.
/// @param[out] remoteIpAddress IP address of remote server in dot-decimal notation.
/// @param[out] remotePort TCP port on which to connect; defaults to DEFAULT_RTSP_PORT.
/// @param[out] localPort UDP port on which to listen for RTP packets; defaults to DEFAULT_RTP_PORT.
/// @param[out] packetLimit Number of packets before teardown.
/// @param[out] timeLimitSec How long before teardown.
/// @param[out] rtspPath Path component of RTSP URI.
/// @param[out] verbosity How much output to generate on console.
/// @param[out] credentials Authentication credentials in the form, username/password.
/// @return Whether command-line arguments are valid.
static bool GetArguments(int argc, const char *argv[],
	string &remoteIpAddress, unsigned &remotePort, unsigned &localPort,
	UINT64 &packetLimit, unsigned &timeLimitSec, string &rtspPath,
	VERB &verbosity, string &credentials)
{
	bool gotArguments = false;

	list<pair<char, string> > options;
	vector<string> positionals;
	for (int i = 1; i < argc; )
	{
		if (strlen(argv[i]) == 2 && argv[i][0] == '-' && isalnum(argv[i][1]) &&
			i + 1 < argc)
		{
			options.push_back(pair<char, string>(argv[i][1], argv[i + 1]));
			i += 2;
		}
		else
		{
			positionals.push_back(argv[i]);
			i += 1;
		}
	}

	if (GetPositionalArguments(positionals, remoteIpAddress, remotePort,
		localPort))
	{
		gotArguments = true;

		for (list<pair<char, string> >::iterator option = options.begin();
			option != options.end(); ++option)
		{
			switch (option->first)
			{
			case COMMAND_LINE_OPTION_CHAR_COUNT:
				{
					istringstream iss(option->second);
					iss >> packetLimit;
					if (iss.fail())
					{
						cerr << "Error: invalid option value "
							<< "(-" << option->first << " " << option->second << ")"
							<< endl;
						gotArguments = false;
					}
				}
				break;

			case COMMAND_LINE_OPTION_CHAR_PATH:
				rtspPath = option->second;
				break;

			case COMMAND_LINE_OPTION_CHAR_TIME:
				{
					istringstream iss(option->second);
					iss >> timeLimitSec;
					if (iss.fail())
					{
						cerr << "Error: invalid option value "
							<< "(-" << option->first << " " << option->second << ")"
							<< endl;
						gotArguments = false;
					}
				}
				break;

			case COMMAND_LINE_OPTION_CHAR_VERB:
				{
					unsigned verbosity_;
					istringstream iss(option->second);
					iss >> verbosity_;
					if (iss.fail() || verbosity_ < VERB_NONE ||
						verbosity_ > VERB_RTSP)
					{
						cerr << "Error: invalid option value "
							<< "(-" << option->first << " " << option->second << ")"
							<< endl;
						gotArguments = false;
					}
					else
					{
						verbosity = static_cast<VERB>(verbosity_);
					}
				}
				break;

			case COMMAND_LINE_OPTION_CHAR_CRED:
				credentials = option->second;
				break;

			default:
				cerr << "Error: unrecognized option "
					<< "(-" << option->first << " " << option->second << ")"
					<< endl;
				gotArguments = false;
				break;
			}
		}
	}

	return gotArguments;
}

///
/// Display command usage on standard output.
///
/// @param[in] programName Program name with optional path and file extension.
static void ShowUsage(string programName)
{
	// Strip path and file extension, if present, from program name.
	size_t periodPosition = programName.find_last_of('.');
	if (periodPosition != string::npos)
	{
		programName.erase(periodPosition);
	}
	size_t lastSlashPosition = programName.find_last_of("/\\");
	if (lastSlashPosition != string::npos)
	{
		programName.erase(0, lastSlashPosition + 1);
	}

	cout << "Establish RTSP/UDP session with server and evaluate packet loss." << endl
		<< endl
		<< programName << " address [port [receive-port]]"
		<< " [-" << COMMAND_LINE_OPTION_CHAR_COUNT << " count]"
		<< " [-" << COMMAND_LINE_OPTION_CHAR_TIME << " time]"
		<< " [-" << COMMAND_LINE_OPTION_CHAR_PATH << " path]"
		<< " [-" << COMMAND_LINE_OPTION_CHAR_VERB << " verbosity]"
		<< " [-" << COMMAND_LINE_OPTION_CHAR_CRED << " credentials]"
		<< endl
		<< endl
		<< "  address        Server \"dot\" IP address." << endl
		<< "  port           Server port (default: " << DEFAULT_RTSP_PORT << ")." << endl
		<< "  receive-port   Port to listen for RTP packets (default: " << DEFAULT_RTP_PORT << ")." << endl
		<< "  -" << COMMAND_LINE_OPTION_CHAR_COUNT << " count       "
		<< "Packets before teardown (0 is unlimited; "
		<< "default: " << DEFAULT_PACKET_LIMIT << ")." << endl
		<< "  -" << COMMAND_LINE_OPTION_CHAR_TIME << " time        "
		<< "Seconds before teardown "
		<< "(default: " << DEFAULT_TIME_LIMIT_SEC<< ")." << endl
		<< "  -" << COMMAND_LINE_OPTION_CHAR_PATH << " path        "
		<< "Path to use in RTSP requests "
		<< "(default: " << DEFAULT_RTSP_PATH << ")." << endl
		<< "  -" << COMMAND_LINE_OPTION_CHAR_VERB << " verbosity   "
		<< "How much info to write to console "
		<< "(0 to 3; default: " << DEFAULT_VERB << ")." << endl
		<< "  -" << COMMAND_LINE_OPTION_CHAR_CRED << " credentials "
		<< "Basic-authentication credentials as username/password." << endl
		;
}

///
/// Get parameters for this session.
///
/// @param[in] argc Argument count.
/// @param[in] argv Argument values.
/// @param[out] remoteIpAddress IP address of remote server in dot-decimal notation.
/// @param[out] remotePort TCP port on which to connect; defaults to DEFAULT_RTSP_PORT.
/// @param[out] localIpAddress IP address in dot-decimal notation of this host's first NIC.
/// @param[out] localPort UDP port on which to listen for RTP packets; defaults to DEFAULT_RTP_PORT.
/// @param[out] packetLimit Number of packets before teardown.
/// @param[out] timeLimitSec How long before teardown.
/// @param[out] rtspPath Path component of RTSP URI.
/// @param[out] verbosity How much output to generate on console.
/// @param[out] credentials Authentication credentials in the form, username/password.
/// @return Whether function succeeded.
static bool GetParameters(int argc, const char *argv[],
	string &remoteIpAddress, unsigned &remotePort,
	string &localIpAddress, unsigned &localPort,
	UINT64 &packetLimit, unsigned &timeLimitSec, string &rtspPath,
	VERB &verbosity, string &credentials)
{
	bool initialized = false;

	if (!GetArguments(argc, argv, remoteIpAddress, remotePort, localPort,
		packetLimit, timeLimitSec, rtspPath, verbosity, credentials))
	{
		ShowUsage(argv[0]);
	}
	else
	{
		WSAData wsaData;
		const int errorCode = WSAStartup(WINSOCK_VERSION_REQUESTED, &wsaData);
		if (errorCode != 0)
		{
			cerr << "Error: winsock could not be initialized"
				<< " (error code " << errorCode << ")" << endl;
		}
		else
		{
			if (GetLocalIpAddress(localIpAddress))
			{
				assert(!localIpAddress.empty());

				initialized = true;
			}
		}
	}

	return initialized;
}

#pragma endregion

///
/// Send request and receive reply on socket.
///
/// @param[in] rtspSocket Socket on which to send request and receive reply.
/// @param[in] verbosity How much output to generate on console.
/// @param[in] request Request to send, e.g., an HTTP or RTSP request.
/// @param[out] reply Reply receive in response to request.
/// @return Whether request was sent and reply received.
static bool SendReceive(SOCKET rtspSocket, VERB verbosity,
	const string &request, string &reply)
{
	bool sentReceived = false;

	if (verbosity >= VERB_RTSP)
	{
		cout << endl << request;
	}

	if (send(rtspSocket, request.c_str(),
		static_cast<int>(request.size()), 0) == request.size())
	{
		char buffer[4096];
		int bytes = recv(rtspSocket, buffer, static_cast<int>(sizeof buffer), 0);
		switch (bytes)
		{
		case SOCKET_ERROR:
		case 0: // (Socket has been gracefully closed.)
			break;

		default:
			reply = string(buffer, bytes);

			if (verbosity >= VERB_RTSP)
			{
				cout << reply;
			}

			sentReceived = true;
			break;
		}
	}

	return sentReceived;
}

///
/// Build an RTSP Request URI.
///
/// @param[in] remoteIpAddress IP address of remote server in dot-decimal notation.
/// @param[in] remotePort UDP port from which server sends RTP packets.
/// @param[in] rtspPath Path component of RTSP URI.
/// @param[in] controlUrl Control component of RTSP URL for subsequent SETUP request.
/// @return Request URI as encoded in returned request line.
static string BuildRequestUri(const string &remoteIpAddress,
	unsigned remotePort, const string &rtspPath, const string &controlUrl)
{
	ostringstream uri;

	// Use base URL
	if (controlUrl.empty() || controlUrl == "*")
	{
		uri << "rtsp://" << remoteIpAddress;
		if (remotePort != DEFAULT_RTSP_PORT)
		{
			uri << ":" << remotePort;
		}
		uri << rtspPath;
	}
	// Use absolute URL
	else if (controlUrl.find("rtsp://") == 0)
	{
		uri << controlUrl;
	}
	// Use relative URL
	else
	{
		uri << "rtsp://" << remoteIpAddress;
		if (remotePort != DEFAULT_RTSP_PORT)
		{
			uri << ":" << remotePort;
		}
		uri << rtspPath << "/" << controlUrl;
	}

	return uri.str();
}

///
/// Base64 encode the given plaintext.
///
/// @param[in] plaintext Plaintext to Base64 encode.
/// @return Base64-encoded version of plaintext.
static string Base64Encode(const string &plaintext)
{
	string ciphertext;
	size_t i = 0;
	unsigned char charArray3[3];
	unsigned char charArray4[4];
	static const std::string base64Chars = 
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";

	for (string::const_iterator it = plaintext.begin(); it != plaintext.end();
		++it)
	{
		charArray3[i++] = *it;
		if (i == 3)
		{
			charArray4[0] = (charArray3[0] & 0xfc) >> 2;
			charArray4[1] = ((charArray3[0] & 0x03) << 4) +
				((charArray3[1] & 0xf0) >> 4);
			charArray4[2] = ((charArray3[1] & 0x0f) << 2) +
				((charArray3[2] & 0xc0) >> 6);
			charArray4[3] = charArray3[2] & 0x3f;

			for (i = 0; i < sizeof charArray4; i++)
			{
				ciphertext += base64Chars[charArray4[i]];
			}

			i = 0;
		}
	}

	if (i > 0)
	{
		for (size_t j = i; j < sizeof charArray3; ++j)
		{
			charArray3[j] = '\0';
		}

		charArray4[0] = (charArray3[0] & 0xfc) >> 2;
		charArray4[1] = ((charArray3[0] & 0x03) << 4) +
			((charArray3[1] & 0xf0) >> 4);
		charArray4[2] = ((charArray3[1] & 0x0f) << 2) +
			((charArray3[2] & 0xc0) >> 6);
		charArray4[3] = charArray3[2] & 0x3f;

		for (size_t j = 0; j < i + 1; ++j)
		{
			ciphertext += base64Chars[charArray4[j]];
		}

		while (i++ < 3)
		{
			ciphertext += '=';
		}
	}

	return ciphertext;
}

static string BasicAuthHeader(const string &credentials)
{
	string authHeader;

	if (!credentials.empty())
	{
		string username;
		string password;
		size_t slashPos = credentials.find('/');
		if (slashPos == string::npos)
		{
			username = credentials;
		}
		else
		{
			username = credentials.substr(0, slashPos);
			password = credentials.substr(slashPos + 1);
		}

		authHeader = "Authorization: Basic " +
			Base64Encode(username + ':' + password) + "\r\n";
	}

	return authHeader;
}

///
/// Send RTSP OPTIONS request and receive reply.
///
/// @param[in] rtspSocket Socket on which to send request and receive reply.
/// @param[in] uri RTSP URI.
/// @param[in] verbosity How much output to generate on console.
/// @param[in] credentials Authentication credentials in the form, username/password.
/// @param[in,out] cSeq Command-sequence number.
/// @return Whether request was sent and reply received.
static bool SendReceiveOptions(SOCKET rtspSocket, const string &uri,
	VERB verbosity, const string &credentials, unsigned &cSeq)
{
	ostringstream request;
	request << "OPTIONS " << uri << " RTSP/1.0\r\n"
		<< "CSeq: " << cSeq++ << "\r\n"
		<< "User-Agent: GetRtsp\r\n"
		<< BasicAuthHeader(credentials)
		<< "\r\n";
	string reply;
	return SendReceive(rtspSocket, verbosity, request.str(), reply);
}

///
/// Send RTSP DESCRIBE request and receive reply.
///
/// @param[in] rtspSocket Socket on which to send request and receive reply.
/// @param[in] uri RTSP URI.
/// @param[in] verbosity How much output to generate on console.
/// @param[in] credentials Authentication credentials in the form, username/password.
/// @param[in,out] cSeq Command-sequence number.
/// @param[out] controlUrl Control component of RTSP URL for subsequent SETUP request.
/// @return Whether request was sent and reply received.
static bool SendReceiveDescribe(SOCKET rtspSocket, const string &uri,
	VERB verbosity, const string &credentials, unsigned &cSeq, string &controlUrl)
{
	bool sentReceived = false;

	ostringstream request;
	request << "DESCRIBE " << uri << " RTSP/1.0\r\n"
		<< "CSeq: " << cSeq++ << "\r\n"
		<< "Accept: application/sdp\r\n"
		<< "User-Agent: GetRtsp\r\n"
		<< BasicAuthHeader(credentials)
		<< "\r\n";
	string reply;
	if (SendReceive(rtspSocket, verbosity, request.str(), reply))
	{
		// Use last control URL in SDP. (Panasonic puts two of them in their
		// SDP. the last one is for video. Coulod be smarter about which one to
		// use, but this works for now.
		size_t next = 0;
		for ( ; ; )
		{
			static const string CONTROL_ATTRIBUTE = "a=control:";

			size_t start = reply.find(CONTROL_ATTRIBUTE, next);
			if (start == string::npos)
			{
				break;
			}

			start += CONTROL_ATTRIBUTE.length();
			size_t end = reply.find('\r', start);
			if (end == string::npos)
			{
				break;
			}

			controlUrl = reply.substr(start, end - start);
			sentReceived = true;

			next = end;
		}
	}

	return sentReceived;
}

///
/// Send RTSP SETUP request and receive reply.
///
/// @param[in] rtspSocket Socket on which to send request and receive reply.
/// @param[in] uri RTSP URI.
/// @param[in] localPort UDP port on which to listen for RTP packets.
/// @param[in] verbosity How much output to generate on console.
/// @param[in] credentials Authentication credentials in the form, username/password.
/// @param[in,out] cSeq Command-sequence number.
/// @param[out] sessionId RTSP session identifier.
/// @return Whether request was sent and reply received.
static bool SendReceiveSetup(SOCKET rtspSocket, const string &uri,
	unsigned localPort, VERB verbosity, const string &credentials,
	unsigned &cSeq, string &sessionId)
{
	bool sentReceived = false;

	ostringstream request;
	request << "SETUP " << uri << " RTSP/1.0\r\n"
		<< "CSeq: " << cSeq++ << "\r\n"
		<< "Transport: RTP/AVP;unicast;client_port=" << localPort << "-" << localPort + 1 << "\r\n"
		<< "User-Agent: GetRtsp\r\n"
		<< BasicAuthHeader(credentials)
		<< "\r\n";
	string reply;
	if (SendReceive(rtspSocket, verbosity, request.str(), reply))
	{
		static const string SESSION_HEADER = "Session: ";

		size_t start = reply.find(SESSION_HEADER);
		if (start != string::npos)
		{
			start += SESSION_HEADER.length();
			size_t end = reply.find('\r', start);
			if (end != string::npos)
			{
				sessionId = reply.substr(start, end - start);

				sentReceived = true;
			}
		}
	}

	return sentReceived;
}

///
/// Send RTSP PLAY request and receive reply.
///
/// @param[in] rtspSocket Socket on which to send request and receive reply.
/// @param[in] uri RTSP URI.
/// @param[in] verbosity How much output to generate on console.
/// @param[in] credentials Authentication credentials in the form, username/password.
/// @param[in,out] cSeq Command-sequence number.
/// @param[in] sessionId RTSP session identifier.
/// @return Whether request was sent and reply received.
static bool SendReceivePlay(SOCKET rtspSocket, const string &uri,
	VERB verbosity, const string &credentials, unsigned &cSeq,
	const string &sessionId)
{
	ostringstream request;
	request << "PLAY " << uri << " RTSP/1.0\r\n"
		<< "CSeq: " << cSeq++ << "\r\n"
		<< "Session: " << sessionId << "\r\n"
		<< "Range: npt=0.000-\r\n"
		<< "User-Agent: GetRtsp\r\n"
		<< BasicAuthHeader(credentials)
		<< "\r\n";
	string reply;
	return SendReceive(rtspSocket, verbosity, request.str(), reply);
}

///
/// Send RTSP TEARDOWN request and receive reply.
///
/// @param[in] rtspSocket Socket on which to send request and receive reply.
/// @param[in] uri RTSP URI.
/// @param[in] verbosity How much output to generate on console.
/// @param[in] credentials Authentication credentials in the form, username/password.
/// @param[in,out] cSeq Command-sequence number.
/// @param[in] sessionId RTSP session identifier.
/// @return Whether request was sent and reply received.
static bool SendReceiveTeardown(SOCKET rtspSocket, const string &uri,
	VERB verbosity, const string &credentials, unsigned &cSeq,
	const string &sessionId)
{
	ostringstream request;
	request << "TEARDOWN " << uri << " RTSP/1.0\r\n"
		<< "CSeq: " << cSeq++ << "\r\n"
		<< "Session: " << sessionId << "\r\n"
		<< "User-Agent: GetRtsp\r\n"
		<< BasicAuthHeader(credentials)
		<< "\r\n";
	string reply;
	return SendReceive(rtspSocket, verbosity, request.str(), reply);
}

///
/// Establish RTSP session.
///
/// @param[in] rtspSocket Socket on which to send RTSP requests and receive replies.
/// @param[in] address IP address of remote server in dot-decimal notation.
/// @param[in] port TCP port on which to connect.
/// @param[in] path Path component of RTSP URI.
/// @param[in] localPort UDP port on which to listen for RTP packets.
/// @param[in] verbosity How much output to generate on console.
/// @param[in] credentials Authentication credentials in the form, username/password.
/// @param[in,out] cSeq Command-sequence number.
/// @param[out] sessionId RTSP session identifier needed by subsequent TEARDOWN request.
/// @return Whether session is established.
static bool EstablishRtspSession(SOCKET rtspSocket,
	const string &address, unsigned port, const string &path,
	unsigned localPort, VERB verbosity, const string &credentials,
	unsigned &cSeq, string &sessionId)
{
	string controlUrl;

	sessionId.clear();

	// Send OPTIONS, DESCRIBE, SETUP, and PLAY requests to establish RTSP
	// session. (We don't really need OPTIONS but do anyway to exercise
	// server.)
	return SendReceiveOptions(rtspSocket,
		BuildRequestUri(address, port, path, ""), verbosity,
		credentials, cSeq) &&

		SendReceiveDescribe(rtspSocket,
		BuildRequestUri(address, port, path, ""), verbosity,
		credentials, cSeq, controlUrl) &&

		SendReceiveSetup(rtspSocket,
		BuildRequestUri(address, port, path, controlUrl), localPort, verbosity,
		credentials, cSeq, sessionId) &&

		SendReceivePlay(rtspSocket,
		BuildRequestUri(address, port, path, ""), verbosity,
		credentials, cSeq, sessionId);
}

///
/// Abolish RTSP session.
///
/// @param[in] rtspSocket Socket on which to send RTSP requests and receive replies.
/// @param[in] address IP address of remote server in dot-decimal notation.
/// @param[in] port TCP port on which to connect.
/// @param[in] path Path component of RTSP URI.
/// @param[in] verbosity How much output to generate on console.
/// @param[in] credentials Authentication credentials in the form, username/password.
/// @param[in,out] cSeq Command-sequence number.
/// @param[in] sessionId RTSP session identifier.
/// @return Whether session was abolished.
static bool AbolishRtspSession(SOCKET rtspSocket,
	const string &address, unsigned port, const string &path,
	VERB verbosity, const string &credentials, unsigned &cSeq,
	const string &sessionId)
{
	// Send TEARDOWN request to cleanly terminate RTSP session.
	return SendReceiveTeardown(rtspSocket,
		BuildRequestUri(address, port, path, ""), verbosity,
		credentials, cSeq, sessionId);
}

///
/// Display session packet-loss results.
///
/// @param[in] packetLossList List of packet-loss incidences during a session.
/// @param[in] received Number of packets received.
/// @param[in] lost Number of packets lost.
/// @param[in] verbosity How much output to generate on console.
static void DisplayResults(const PacketLossList &packetLossList,
	UINT64 received, UINT64 lost, VERB verbosity)
{
	if (verbosity >= VERB_LIST && !packetLossList.empty())
	{
		cout << endl;

		for (PacketLossList::const_iterator it = packetLossList.begin();
			it != packetLossList.end(); it++)
		{
			const UINT64 packetsSent = (*it).received + (*it).lost;
			const double packetLoss =
				static_cast<double>((*it).lost) / packetsSent;
			WORD difference = (*it).current - (*it).previous;
			cout << "  "
				<< (*it).previous << " .. "
				<< difference - 1 << " .. "
				<< (*it).current << " "
				<< fixed << setprecision(2)
				<< packetLoss * 100. << "%" << endl;
		}
	}

	UINT64 expected = received + lost;
	const double packetLoss = expected == 0 ? 0. :
		static_cast<double>(lost) / expected;
	cout << endl
		<< "  Expected: " << expected << endl
		<< "  Received: " << received << endl
		<< "  Lost: " << lost << endl
		<< "  Gaps: " << packetLossList.size() << endl
		<< fixed << setprecision(2)
		<< "  Packet loss: " << packetLoss * 100. << "%"
		<< endl;
}

///
/// Initialize socket on which we expect to receive RTP packets.
///
/// @param[in] localIpAddress IP address in dot-decimal notation of this host's first NIC.
/// @param[in] localPort UDP port on which to listen for RTP packets.
/// @param[out] rtpSocket Socket on which we expect to receive RTP packets.
/// @return Whether the socket is initialized and ready to receive packets on.
static bool InitializeRtpSocket(
	const string &localIpAddress, unsigned localPort, SOCKET &rtpSocket)
{
	bool initialized = false;

	rtpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (rtpSocket == INVALID_SOCKET)
	{
		ReportSocketError(WSAGetLastError(), "could not create RTP socket");
	}
	else
	{
		SOCKADDR_IN local;
		local.sin_family = AF_INET;
		local.sin_port = htons(localPort);
		local.sin_addr.s_addr = htonl(INADDR_ANY);//inet_addr(localIpAddress.c_str());
		if (bind(rtpSocket, reinterpret_cast<SOCKADDR *>(&local),
			sizeof local) == SOCKET_ERROR)
		{
			ReportSocketError(WSAGetLastError(), "could not bind RTP socket");
		}
		else
		{
			initialized = true;
		}
	}

	return initialized;
}

///
/// Process RTP packet.
///
/// @param[in] buffer RTP packet.
/// @param[in] bytes Number of bytes in RTP packet or SOCKET_ERROR if packet truncated.
/// @param[in,out] previous Sequence number of previously received RTP packet.
/// @param[in,out] previousSet Whether we have encountered an RTP packet--whether "previous" has sequence number.
/// @param[in,out] received Number of RTP packets received so far during this session.
/// @param[in,out] lost Number of RTP packets lost so far during this session.
/// @param[in] verbosity How much output to generate on console.
/// @param[out] packetLossList List of packet-loss incidences during session.
static void ProcessRtpPacket(char *buffer, int bytes,
	WORD &previous, bool &previousSet, UINT64 &received, UINT64 &lost,
	PacketLossList &packetLossList)
{
	assert(bytes == SOCKET_ERROR || bytes >= 12);

	// Update number of received packets.
	++received;

	// Extract RTP sequence number.
	WORD current = buffer[2] << 8 |
		static_cast<unsigned char>(buffer[3]);

	// If we have a previous sequence number against which we can compare this
	// one, calculate the difference between the two. If off by more than 1,
	// we've lost some intervening packets, so add to list for subsequent
	// display after session is over.
	if (previousSet)
	{
		WORD difference = current - previous;
		if (difference > 1)
		{
			// Update number of lost packets.
			lost += difference - 1;

			// Populate struct holding info about this gap in sequence numbers
			// and add to list.
			const PacketLoss packetLossEntry =
				{previous, current, received, lost};
			packetLossList.push_back(packetLossEntry);
		}
	}
	previous = current;
	previousSet = true;
}

///
/// Process RTP packets.
///
/// @param[in] localIpAddress IP address in dot-decimal notation of this host's first NIC.
/// @param[in] localPort UDP port on which to listen for RTP packets.
/// @param[in] packetLimit Number of packets before teardown.
/// @param[in] timeLimitSec How long before teardown.
/// @param[out] packetLossList List of packet-loss incidences during session.
/// @param[out] received Received RTP packets.
/// @param[out] lost Lost RTP packets.
static void ProcessRtpPackets(const string &localIpAddress, unsigned localPort,
	UINT64 packetLimit, unsigned timeLimitSec,
	PacketLossList &packetLossList, UINT64 &received, UINT64 &lost)
{
	assert(packetLossList.empty());
	packetLossList.clear();
	assert(received == 0 && lost == 0);
	received = 0;
	lost = 0;

	SOCKET rtpSocket;
	if (InitializeRtpSocket(localIpAddress, localPort, rtpSocket))
	{
		WORD previous = 0; // Sequence number of previous RTP packet.
		bool previousSet = false; // Whether "previous" has a sequence number.
		DWORD stopTime = GetTickCount() + timeLimitSec * 1000; // When to stop.

		// Process RTP packets until sotp time or packet limit (if any) reached.
		for (UINT64 i = 0; GetTickCount() < stopTime &&
			(packetLimit == 0 || i < packetLimit); ++i)
		{
			char buffer[RTP_PACKET_BUFFER_LENGTH];
			int bytes = recv(rtpSocket, buffer, sizeof buffer, 0);
			// Socket error that's not because packet had to be truncated.
			if (bytes == SOCKET_ERROR && WSAGetLastError() != WSAEMSGSIZE)
			{
				ReportSocketError(WSAGetLastError(),
					"could not read RTP socket");
				break;
			}
			else if (bytes == 0)
			{
				// (I don't think this can actually happen with a
				// connectionless socket since there is no connection to
				// close.)
				ReportSocketError(WSAGetLastError(),
					"RTP socket closed gracefully");
				break;
			}
			else
			{
				// Look for gaps in sequence numbers.
				ProcessRtpPacket(buffer, bytes,
					previous, previousSet, received, lost, packetLossList);
			}
		}
	}
}

int _tmain(int argc, const char *argv[])
{
	string remoteIpAddress;
	unsigned remotePort;
	string localIpAddress;
	unsigned localPort;
	UINT64 packetLimit = DEFAULT_PACKET_LIMIT;
	unsigned timeLimitSec = DEFAULT_TIME_LIMIT_SEC;
	string rtspPath = DEFAULT_RTSP_PATH;
	VERB verbosity = DEFAULT_VERB;
	string credentials;

	if (GetParameters(argc, argv, remoteIpAddress, remotePort,
		localIpAddress, localPort, packetLimit, timeLimitSec, rtspPath,
		verbosity, credentials))
	{
		if (verbosity >= VERB_SUMMARY)
		{
			cout << "Sent request to "
				<< remoteIpAddress << ":" << remotePort
				<< "; receiving video at "
				<< localIpAddress << ":" << localPort
				<< endl;
		}

		SOCKET rtspSocket;
		rtspSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (rtspSocket == INVALID_SOCKET)
		{
			ReportSocketError(WSAGetLastError(),
				"could not create RTSP socket");
		}
		else
		{
			sockaddr_in address;
			address.sin_family = AF_INET;
			address.sin_addr.s_addr = inet_addr(remoteIpAddress.c_str());
			address.sin_port = htons(remotePort);

			if (connect(rtspSocket,
				reinterpret_cast<sockaddr *>(&address), sizeof address) ==
				SOCKET_ERROR)
			{
				ReportSocketError(WSAGetLastError(),
					"could not connect to server");
			}
			else
			{
				const DWORD RECEIVE_TIMEOUT = 500 * 1000;
				if (setsockopt(rtspSocket, SOL_SOCKET, SO_RCVTIMEO,
					reinterpret_cast<const char *>(&RECEIVE_TIMEOUT),
					sizeof RECEIVE_TIMEOUT) == SOCKET_ERROR)
				{
					ReportSocketError(WSAGetLastError(),
						"could not set receive timeout");
				}
				else
				{
					// (UINT64 large enough to count packets for almost year.)
					UINT64 received = 0; // Received RTP packets.
					UINT64 lost = 0; // Lost RTP packets.

					///
					/// List of packet-loss incidences during session.
					///
					/// @note packet-loss info is accumulated here during the
					/// session and then displayed after the session has ended.
					/// It is not displayed during the session to avoid any
					/// extra CPU overhead, e.g., synchronously writing
					/// information to the console window.
					PacketLossList packetLossList;

					unsigned cSeq = 1;
					string sessionId;

					if (EstablishRtspSession(rtspSocket, remoteIpAddress,
						remotePort, rtspPath, localPort, verbosity,
						credentials, cSeq, sessionId))
					{
						ProcessRtpPackets(localIpAddress, localPort,
							packetLimit, timeLimitSec,
							packetLossList, received, lost);
					}

					if (!sessionId.empty())
					{
						AbolishRtspSession(rtspSocket, remoteIpAddress,
							remotePort, rtspPath, verbosity, credentials,
							cSeq, sessionId);

						if (verbosity > VERB_NONE)
						{
							DisplayResults(packetLossList, received, lost,
								verbosity);
						}
					}
				}
			}
		}
	}

	return 0;
}

