#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <map>
#include <vector>
#include <algorithm>
#include <iostream>
#include <memory>
#include <cctype>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <openssl/ssl.h>
#include <openssl/err.h>
// === Cache: new headers
#include <filesystem>
#include <fstream>
#include <sstream>

// Enable if you want debugging to be printed, see examble below.
// Alternative, pass CFLAGS=-DDEBUG to make, make CFLAGS=-DDEBUG
#define DEBUG

namespace fs = std::filesystem;

// Return current local time formatted as "yy-mm-dd hh:mm:ss"
static std::string now_local_yy_mm_dd_hh_mm_ss()
{
    using namespace std::chrono;
    auto now = system_clock::now();
    std::time_t t = system_clock::to_time_t(now);
    std::tm local_tm{};
#if defined(_WIN32)
    localtime_s(&local_tm, &t); // thread-safe on Windows
#else
    local_tm = *std::localtime(&t); // use localtime_r if available
    // Alternatively (POSIX): localtime_r(&t, &local_tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&local_tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

struct Url {
    std::string scheme; // "http" or "https"
    std::string host;   // hostname or [IPv6]
    std::string port;   // "80" / "443" / or explicit
    std::string path;   // always starts with '/', at least "/"
};

struct ChunkReadStats {
    size_t socket_bytes = 0;   // total bytes read from socket during chunked phase
    size_t body_bytes = 0;     // total bytes appended to 'acc' (payload only)
    size_t chunks = 0;         // number of chunks successfully appended
    size_t last_chunk_size = 0;
    bool eof_in_size_line = false;
    bool eof_in_chunk_data = false;
    bool missing_crlf_after_chunk = false;
};


static void to_lower_inplace(std::string &s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
}


static bool is_default_port(const Url& u) {
    if (u.scheme == "https") return (u.port == "443");
    if (u.scheme == "http")  return (u.port == "80");
    return false;
}

static bool validate_scheme(const Url& u){
    if (u.scheme == "https") return true;
    if (u.scheme == "http")  return true;
    return false;
}

// Simple URL parser supporting IPv6 literals in brackets, e.g., https://[2001:db8::1]:8443/path
static bool parse_url(const std::string& input, Url& out, std::string& error) {
    auto pos = input.find("://");
    if (pos == std::string::npos) {
        error = "Invalid URL: missing '://'";
        return false;
    }
    out.scheme = input.substr(0, pos);
    to_lower_inplace(out.scheme);

    if (!validate_scheme(out)){
        return false;
    }
    
    size_t host_start = pos + 3;
    size_t path_start = std::string::npos;
    size_t host_end   = std::string::npos;

    // IPv6 literal?
    if (host_start < input.size() && input[host_start] == '[') {
        size_t rb = input.find(']', host_start);
        if (rb == std::string::npos) {
            error = "Invalid URL: missing closing ']' for IPv6 address";
            return false;
        }
        out.host = input.substr(host_start, rb - host_start + 1); // include [ ]
        if (rb + 1 < input.size() && input[rb + 1] == ':') {
            // port after IPv6
            size_t port_begin = rb + 2;
            path_start = input.find('/', port_begin);
            if (path_start == std::string::npos) {
                out.port = input.substr(port_begin);
                out.path = "/";
                goto finalize_defaults;
            } else {
                out.port = input.substr(port_begin, path_start - port_begin);
            }
        } else {
            // no port, next '/' starts path
            path_start = input.find('/', rb + 1);
        }
        host_end = (path_start == std::string::npos) ? input.size() : path_start; // host already set
    } else {
        // IPv4 or name: host[:port][/path]
        path_start = input.find('/', host_start);
        host_end   = (path_start == std::string::npos) ? input.size() : path_start;
        size_t colon = input.find(':', host_start);
        if (colon != std::string::npos && colon < host_end) {
            out.host = input.substr(host_start, colon - host_start);
            out.port = input.substr(colon + 1, host_end - (colon + 1));
        } else {
            out.host = input.substr(host_start, host_end - host_start);
        }
    }

    if (out.host.empty()) {
        error = "Invalid URL: empty host";
        return false;
    }

    if (path_start == std::string::npos) {
        out.path = "/";
    } else {
        out.path = input.substr(path_start);
        if (out.path.empty()) out.path = "/";
    }

finalize_defaults:
    // Default port by scheme
    if (out.port.empty()) {
        if (out.scheme == "https") out.port = "443";
        else if (out.scheme == "http") out.port = "80";
        else {
            error = "Unsupported scheme: " + out.scheme;
            return false;
        }
    }

    // Validate port
    if (!std::all_of(out.port.begin(), out.port.end(), ::isdigit)) {
        error = "Invalid port: " + out.port;
        return false;
    }

    return true;
}

bool try_connect(int *sockfd, const char *Desthost, const char *Destport)
{
  //variable that will be filled with data
  struct addrinfo *res, *pInfo;

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  int addrinfo_status = getaddrinfo(Desthost, Destport, &hints, &res);
  if(addrinfo_status != 0)
  {
    printf("\nERROR: getaddrinfo Failed\n");
    printf("Returned: %d\n", addrinfo_status);
    return false;
  }

  #ifdef DEBUG
  printf("getaddrinfo Succeded!\n");
  #endif

  for(pInfo = res; pInfo != NULL; pInfo = pInfo->ai_next)
  {
    *sockfd = socket(pInfo->ai_family, pInfo->ai_socktype, pInfo->ai_protocol);
    if(*sockfd != -1)
    {
      break;
    }
  }

  if(*sockfd == -1)
  {
    printf("\nERROR: Socket creation Failed\n");
    printf("Returned: %d\n", *sockfd);
    return false;
  }

  //Set options for socket
  struct timeval tv;
  tv.tv_sec = 10;
  tv.tv_usec = 0;
  setsockopt(*sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  #ifdef DEBUG
  printf("Socket creation Succeded!\n");
  #endif

  int connect_status = connect(*sockfd, pInfo->ai_addr, pInfo->ai_addrlen);
  if(connect_status != 0)
  {
    printf("\nERROR: RESOLVE ISSUE\n");
    printf("Returned: %d\n", connect_status);
    return false;
  }

  #ifdef DEBUG
  printf("Connection Succeded!\n");
  #endif

  freeaddrinfo(res);
  return true;
}

std::string gen_get_request(std::string& host, std::string& path)
{
    std::ostringstream request;
    request << "GET " << (path.empty() ? "/" : path) << " HTTP/1.1\r\n";
    request << "Host: " << host << "\r\n";
    request << "Connection: close\r\n";
    request << "\r\n";
    return request.str();
}

int get_code(const std::string& header)
{
    char http[10];
    int code = 0;
    std::sscanf(header.c_str(), "%s %d", http, &code);
    return code;
}

std::string get_redirect_url(const std::string& header)
{
    size_t pos = header.find("Location:");
    if(pos == std::string::npos)
    {
        return "";
    }

    pos += 10; //Move past Location: and a space
    size_t end = header.find("\r\n", pos);
    if(end == std::string::npos)
    {
        end = header.size();
    }
    
    return header.substr(pos, end - pos);
}

bool case_http(int& sockfd, Url& url, std::string& out)
{
    std::string request = gen_get_request(url.host, url.path);

    ssize_t bytes_sent = send(sockfd, request.c_str(), request.size(), 0);
    if(bytes_sent < 0)
    {
        std::printf("error send error\n");
        return false;
    }

    char recv_buffer[1024];
    std::string response;

    ssize_t bytes_recieved;
    while((bytes_recieved = recv(sockfd, recv_buffer, sizeof(recv_buffer) - 1, 0)) > 0)
    {
        recv_buffer[bytes_recieved] = '\0';
        response += recv_buffer;
    }
    if(bytes_recieved < 0)
    {
        std::printf("error recv error!\n");
        return false;
    }

    size_t sep = response.find("\r\n\r\n");
    std::string header = response.substr(0, sep);
    std::string body = response.substr(sep + 4);

    get_code(header);
    std::cout << "New url: " << get_redirect_url(header) << "\n" << std::endl;
    out = get_redirect_url(header);
    return true;
}

int main(int argc, char* argv[]) {
    bool cache_enabled = false;
    std::string url_str;
    std::string output_file;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--cache") cache_enabled = true;
	else if (a == "-o" || a == "--output") {
            if (i + 1 >= argc) {
	      std::fprintf(stdout, "-o/--output requires a filename (or - for stdout)\n");
	      std::fprintf(stdout, "Usage: %s [--cache] [-o <file|->] url\n", argv[0]);
	      return EXIT_FAILURE;
            }
            output_file = argv[++i];
        }
        else if (!a.empty() && a[0] == '-') {
            std::fprintf(stdout, "Error Unknown option: %s\n", a.c_str());
            std::fprintf(stdout, "Usage: %s [--cache] -o <file>|-> url\n", argv[0]);
            return EXIT_FAILURE;
        } else {
            url_str = a;
        }
    }
    if (url_str.empty()) {
        std::fprintf(stdout, "Usage: %s [--cache] url\n", argv[0]);
        return EXIT_FAILURE;
    }

    Url url;
    std::string error;
    if (!parse_url(url_str, url, error)) {
        std::fprintf(stdout, "ERROR URL parse error: %s\n", error.c_str());
        return EXIT_FAILURE;
    }

    std::printf("Protocol: %s, Host %s, port = %s, path = %s, ",
                url.scheme.c_str(), url.host.c_str(), url.port.c_str(), url.path.c_str());
    std::printf("Output: %s\n", output_file.c_str());

    const int max_redirects = 10;
    int redirects = 0;
    using clock = std::chrono::steady_clock;

    auto t1 = clock::now();
    
    /* do stuff */
    int resp_body_size=0xFACCE;

    int sockfd;

    while(redirects < max_redirects)
    {
        bool connection_status = try_connect(&sockfd, url.host.c_str(), url.port.c_str());
        if(!connection_status)
        {
            return EXIT_FAILURE;
        }

        bool case_status;
        std::string redirect_url = "";
        if(strncmp(url.scheme.c_str(), "http", 4) == 0)
        {
            case_status = case_http(sockfd, url, redirect_url);
            printf("The string: %s\n", redirect_url.c_str());
        }
        else if(strncmp(url.scheme.c_str(), "https", 5) == 0)
        {
            printf("https is here!\n");
        }

        //check if im done
        if(case_status)
        {
            break;
        }
        redirects += 10;

        if (!parse_url(redirect_url, url, error)) {
            std::fprintf(stdout, "ERROR URL parse error: %s\n", error.c_str());
            close(sockfd);
            return EXIT_FAILURE;
        }
    }
    
    if(redirects >= 10)
    {
        std::cout << "error too many redirects!" << std::endl;
        return EXIT_FAILURE;
    }

    auto t2 = clock::now();
    std::chrono::duration<double> diff = t2 - t1; // seconds
    std::cout << std::fixed << std::setprecision(6);
    std::cout << now_local_yy_mm_dd_hh_mm_ss() << " " << url_str << " " << resp_body_size << " [bytes] " << diff.count()
              << " [s] " << (8*resp_body_size/diff.count())/1e6 << " [Mbps]\n";



    close(sockfd);
    return EXIT_SUCCESS;
}
