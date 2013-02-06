/**
 * HTTP Server - use for static content
 * v 2.25
 */
#include <event.h>
#include <evhttp.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <netinet/in.h>
#include <iostream>
#include <map>

#include <malloc.h>

#include <sys/stat.h>

#include "include/zlib/zlib.h"
#include "include/inih_r26/cpp/INIReader.h"

using namespace std;

pthread_mutex_t lock_cache;

struct CacheFile
{
   void *buffer;
   string content_type;
   bool is_compressed;
   unsigned int len_buffer;
   unsigned long time_access_cache;
   unsigned long file_time_last_modified;
};

unsigned int total_size_cache_in_memory = 0;
map<string, CacheFile> map_cache_file;
map<string, CacheFile>::iterator map_cache_file_it;

//-----------------------------------------------------------------------

void *reallocf(void* ptr, size_t size)
{
    void *newptr = realloc(ptr, size);
    if (NULL == newptr && ptr != NULL)
    {
        free(ptr);
        ptr = NULL;
    }

    return newptr;
}

/*unsigned long get_file_size(const char *filepath)
{
    FILE * f = fopen(filepath, "r");

    if(f == NULL)
    {
        return 0;
    }

    fseek(f, 0, SEEK_END);
    unsigned long len = (unsigned long)ftell(f);
    fclose(f);
    return len;
}*/

unsigned long get_file_time_last_modified(const char *filepath)
{
    struct stat b;
    if (!stat(filepath, &b))
    {
        return b.st_mtime;
    }
    return 0;
}

bool file_exists(string path)
{
    FILE *file = fopen(path.c_str(), "r");
    if(file != NULL)
    {
        fclose(file);
        return true;
    }
    return false;
}
/// CACHE FUNCTION ------------------------------------------------
bool cache__is_exists(string path)
{
    map<string, CacheFile>::iterator t = map_cache_file.find(path);

    if(t != map_cache_file.end())
    {
        return true;
    }

    return false;
}

void cache__remove(string path)
{
    map<string, CacheFile>::iterator t = map_cache_file.find(path);

    if(t != map_cache_file.end())
    {
        total_size_cache_in_memory -= (*t).second.len_buffer;
        free((*t).second.buffer);

        map_cache_file.erase(t);

        //printf("<< cache__remove: %s\n", path.c_str());
    }
}

map<string, CacheFile>::iterator cache__get_last_file_accept()
{
    map<string, CacheFile>::iterator result = map_cache_file.end();
    map<string, CacheFile>::iterator i;

    unsigned long _curr_time = time(NULL);
    unsigned long _max_time = 0, _diff_time;

    for(i = map_cache_file.begin(); i != map_cache_file.end(); i++)
    {
        _diff_time = _curr_time - (*i).second.time_access_cache;
        if(_max_time < _diff_time)
        {
            _max_time = _diff_time;
            result = i;
        }
    }

    return result;
}

bool cache__is_file_added(unsigned int len_buffer, unsigned int size_cache)
{
    if(len_buffer <= size_cache)
    {
        return true;
    }

    return false;
    //unsigned int diff = size_cache - total_size_cache_in_memory;

    /*if( len_buffer <= diff )
    {
        return true;
    }
    else
    {
        map<string, CacheFile>::iterator t = cache__get_last_file_accept();

        diff = size_cache - total_size_cache_in_memory - (*t).second.len_buffer;
        if( len_buffer <= diff )
        {
            return true;
        }
    }

    return false;*/
}

void cahce__add_in_cache(string path, CacheFile data_add, unsigned int size_cache)
{
    if(!(data_add.len_buffer <= size_cache))
    {
        return;
    }

    if(! cache__is_exists(path))
    {
        unsigned int diff;

        while(true)
        {
            diff = size_cache - total_size_cache_in_memory;

            if( ! (data_add.len_buffer <= diff ))
            {
                map<string, CacheFile>::iterator t = cache__get_last_file_accept();

                if(t != map_cache_file.end())
                {
                    cache__remove( (*t).first );
                }
            }
            else
            {
                break;
            }

            if(map_cache_file.size() == 0)
            {
                break;
            }
        }

        map_cache_file[path] = data_add;
        total_size_cache_in_memory += data_add.len_buffer;
    }
}
/// ---------------------------------------------------------------
bool is_directory(string pathname)
{
    struct stat sb;

    if (stat(pathname.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode))
    {
        return true;
    }
    return false;
}
// ----------------------------------------------------------------------------
string urlDecode(string &SRC)
{
    string ret;
    char ch;
    unsigned int i, ii;
    for(i=0; i<SRC.length(); i++)
    {
        if (int(SRC[i])==37)
        {
            sscanf(SRC.substr(i+1,2).c_str(), "%x", &ii);
            ch=static_cast<char>(ii);
            ret+=ch;
            i=i+2;
        }
        else
        {
            ret+=SRC[i];
        }
    }
    return (ret);
}

///------------------------------------------------------------------------------------
namespace servers
{
    namespace util
    {
        class HTTPServer
        {
            public:
              HTTPServer();
              ~HTTPServer() {}
              int serv(int port, int nthreads);

            protected:
              static void* Dispatch(void *arg);
              static void GenericHandler(struct evhttp_request *req, void *arg);
              void ProcessRequest(struct evhttp_request *request);
              bool HttpParseContentRangeHeader(struct evhttp_request *_req, int64_t *rangefirst, int64_t *rangelast, int *replycode, int64_t filesize);
              int BindSocket(int port);

              map<string, string> ext_types;

              /// CONFIG
              string CONFIG_MAIN_OFFSET_PATH;
              string CONFIG_EXT_LIST_COMPRESS_FILE;
              string CONFIG_SERVER_NAME;
              unsigned int    CONFIG_MINIMAL_SIZE_COMPRESS_FILE;
              int    CONFIG_CACHE_SIZE;
              int    CONFIG_PORT;
              int    CONFIG_COUNT_THREADS;
              bool   CONFIG_USE_CACHE;
        };

        HTTPServer::HTTPServer()
        {
            // Ignore SIGPIPE
            signal(SIGPIPE, SIG_IGN);

            this->ext_types["htm"]   = "text/html";
            this->ext_types["html"]  = "text/html";
            this->ext_types["stm"]   = "text/html";
            this->ext_types["jad"]   = "text/vnd.sun.j2me.app-descriptor";
            this->ext_types["bas"]   = "text/plain";
            this->ext_types["c"]     = "text/x-c";
            this->ext_types["h"]     = "text/plain";
            this->ext_types["txt"]   = "text/plain";
            this->ext_types["css"]   = "text/css";
            this->ext_types["s"]     = "text/x-asm";
            this->ext_types["curl"]  = "text/vnd.curl";
            this->ext_types["dcurl"] = "text/vnd.curl.dcurl";
            this->ext_types["java"]  = "text/x-java-source,java";
            this->ext_types["ttl"]   = "text/turtle";

            this->ext_types["jpg"]   = "image/jpeg";
            this->ext_types["jpe"]   = "image/jpeg";
            this->ext_types["jpeg"]  = "image/jpeg";
            this->ext_types["png"]   = "image/png";
            this->ext_types["tif"]   = "image/tiff";
            this->ext_types["tiff"]  = "image/tiff";
            this->ext_types["ico"]   = "image/x-icon";
            this->ext_types["bmp"]   = "image/bmp";
            this->ext_types["gif"]   = "image/gif";
            this->ext_types["ief"]   = "image/ief";
            this->ext_types["djvu"]  = "image/vnd.djvu";
            this->ext_types["djv"]   = "image/vnd.djvu";
            this->ext_types["svg"]   = "image/svg+xml";
            this->ext_types["wbmp"]  = "image/vnd.wap.wbmp";

            this->ext_types["wav"]   = "audio/x-wav";
            this->ext_types["aif"]   = "audio/x-aiff";
            this->ext_types["aifc"]  = "audio/x-aiff";
            this->ext_types["aiff"]  = "audio/x-aiff";
            this->ext_types["m3u"]   = "audio/x-mpegurl";
            this->ext_types["ra"]    = "audio/x-pn-realaudio";
            this->ext_types["ram"]   = "audio/x-pn-realaudio";
            this->ext_types["kar"]   = "audio/midi";
            this->ext_types["mid"]   = "audio/midi";
            this->ext_types["midi"]  = "audio/midi";

            this->ext_types["js"]    = "application/javascript";
            this->ext_types["json"]  = "application/json";
            this->ext_types["zip"]   = "application/zip";
            this->ext_types["z"]     = "application/x-compress";
            this->ext_types["cpio"]  = "application/x-cpio";
            this->ext_types["gz"]    = "application/x-gzip";
            this->ext_types["tgz"]   = "application/x-gzip";
            this->ext_types["bz"]    = "application/x-bzip";
            this->ext_types["bz2"]   = "application/x-bzip2";
            this->ext_types["dvi"]   = "application/x-dvi";
            this->ext_types["gtar"]  = "application/x-gtar";
            this->ext_types["hdf"]   = "application/x-hdf";
            this->ext_types["iii"]   = "application/x-iphone";
            this->ext_types["js"]    = "application/x-javascript";
            this->ext_types["mdb"]   = "application/x-msaccess";
            this->ext_types["dll"]   = "application/x-msdownload";
            this->ext_types["tcl"]   = "application/x-tcl";
            this->ext_types["tar"]   = "application/x-tar";
            this->ext_types["sh"]    = "application/x-sh";
            this->ext_types["rar"]   = "application/x-rar-compressed";
            this->ext_types["7z"]    = "application/x-7z-compressed";
            this->ext_types["mmf"]   = "application/x-smaf";
            this->ext_types["ace"]   = "application/x-ace-compressed";
            this->ext_types["pdf"]   = "application/pdf";
            this->ext_types["ppd"]   = "application/vnd.cups-ppd";
            this->ext_types["xpi"]   = "application/x-xpinstall";
            this->ext_types["exe"]   = "application/exe";
            this->ext_types["apk"]   = "application/vnd.android.package-archive";
            this->ext_types["torrent"]= "application/x-bittorrent";
            this->ext_types["csh"]   = "application/x-csh";
            this->ext_types["xar"]   = "application/vnd.xara";
            this->ext_types["dvi"]   = "application/x-dvi";
            this->ext_types["dtd"]   = "application/xml-dtd";
            this->ext_types["texinfo"]  = "application/x-texinfo";
            this->ext_types["gnumeric"] = "application/x-gnumeric";
            this->ext_types["tpl"]   = "application/vnd.groove-tool-template";
            this->ext_types["jar"]   = "application/java-archive";
            this->ext_types["docx"]  = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
            this->ext_types["doc"]   = "application/x-doc";
            this->ext_types["src"]   = "application/x-wais-source";
            this->ext_types["db"]    = "application/vnd.osgi.dp";
            this->ext_types["otf"]   = "application/x-font-otf";
            this->ext_types["ott"]   = "application/vnd.oasis.opendocument.text-template";
            this->ext_types["odt"]   = "application/vnd.oasis.opendocument.text";
            this->ext_types["ext"]   = "application/vnd.novadigm.ext";
            this->ext_types["ttf"]   = "application/x-font-ttf";

            this->ext_types["csml"]  = "chemical/x-csml";
            this->ext_types["cml"]   = "chemical/x-cml";
            this->ext_types["cdx"]   = "chemical/x-cdx";

            this->ext_types["mp2"]   = "video/mpeg";
            this->ext_types["mpa"]   = "video/mpeg";
            this->ext_types["mpe"]   = "video/mpeg";
            this->ext_types["mpeg"]  = "video/mpeg";
            this->ext_types["mpg"]   = "video/mpeg";
            this->ext_types["mpv2"]  = "video/mpeg";
            this->ext_types["mp4"]   = "video/mp4";
            this->ext_types["movie"] = "video/x-sgi-movie";
            this->ext_types["wmv"]   = "video/x-ms-wmv";
            this->ext_types["3gp"]   = "video/3gpp";
            this->ext_types["avi"]   = "video/x-msvideo";
            this->ext_types["viv"]   = "video/vnd.vivo";

            this->ext_types["mov"]   = "video/quicktime";
            this->ext_types["qt"]    = "video/quicktime";

            this->ext_types["asf"]   = "video/x-ms-asf";
            this->ext_types["asr"]   = "video/x-ms-asf";
            this->ext_types["asx"]   = "video/x-ms-asf";

            this->ext_types["flr"]   = "x-world/x-vrml";
            this->ext_types["vrml"]  = "x-world/x-vrml";
            this->ext_types["wrl"]   = "x-world/x-vrml";
            this->ext_types["wrz"]   = "x-world/x-vrml";
            this->ext_types["xaf"]   = "x-world/x-vrml";
            this->ext_types["xof"]   = "x-world/x-vrml";

            this->ext_types["dwf"]   = "model/vnd.dwf";

            this->CONFIG_USE_CACHE                  = true;
            this->CONFIG_CACHE_SIZE                 = 1024*64;
            this->CONFIG_MAIN_OFFSET_PATH           = "";
            this->CONFIG_MINIMAL_SIZE_COMPRESS_FILE = 102400;// _file size < 100Kb
            this->CONFIG_EXT_LIST_COMPRESS_FILE     = "txt,h,cpp,c,xml,html,ini,log,css,js";
            this->CONFIG_SERVER_NAME                = "TEST_SERVER";

            //printf("file_exists('config.ini'): %d\n", file_exists("config.ini"));

            if(file_exists("config.ini"))
            {
                INIReader reader("config.ini");

                this->CONFIG_MAIN_OFFSET_PATH           = reader.Get("main", "path_to_dir", "");
                this->CONFIG_MINIMAL_SIZE_COMPRESS_FILE = reader.GetInteger("main", "minimal_size_compress_file", this->CONFIG_MINIMAL_SIZE_COMPRESS_FILE);

                this->CONFIG_USE_CACHE                  = reader.GetBoolean("main", "use_memory_cache_size", this->CONFIG_USE_CACHE);
                this->CONFIG_CACHE_SIZE                 = reader.GetInteger("main", "memory_cache_size", this->CONFIG_CACHE_SIZE);

                this->CONFIG_EXT_LIST_COMPRESS_FILE     = reader.Get("main", "compress_file_extensions", this->CONFIG_EXT_LIST_COMPRESS_FILE);
                this->CONFIG_SERVER_NAME                = reader.Get("main", "server_name", this->CONFIG_SERVER_NAME);
            }
        }

        int HTTPServer::BindSocket(int port)
        {
          int r;
          int nfd;
          nfd = socket(AF_INET, SOCK_STREAM, 0);

          if (nfd < 0)
          {
            return -1;
          }

          int one = 1;
          r = setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(int));

          struct sockaddr_in addr;
          memset(&addr, 0, sizeof(addr));
          addr.sin_family = AF_INET;
          addr.sin_addr.s_addr = INADDR_ANY;
          addr.sin_port = htons(port);

          r = bind(nfd, (struct sockaddr*)&addr, sizeof(addr));

          if (r < 0)
          { return -1; }

          r = listen(nfd, 10240);

          if (r < 0)
          { return -1; }

          int flags;
          if ((flags = fcntl(nfd, F_GETFL, 0)) < 0 || fcntl(nfd, F_SETFL, flags | O_NONBLOCK) < 0)
          { return -1; }

          return nfd;
        }

        // ----------------------------------------------------------------------------------------------
        int HTTPServer::serv(int port, int nthreads)
        {
              int r;
              int nfd = BindSocket(port);

              if (nfd < 0)
              { return -1; }

              pthread_t ths[nthreads];

              for (int i = 0; i < nthreads; i++)
              {
                    struct event_base *base = event_init();

                    if (base == NULL)
                    { return -1; }

                    struct evhttp *httpd = evhttp_new(base);

                    if (httpd == NULL)
                    { return -1; }

                    r = evhttp_accept_socket(httpd, nfd);

                    if (r != 0)
                    { return -1; }

                    evhttp_set_gencb(httpd, HTTPServer::GenericHandler, this);
                    r = pthread_create(&ths[i], NULL, HTTPServer::Dispatch, base);

                    if (r != 0)
                    { return -1; }
              }

              for (int i = 0; i < nthreads; i++)
              {
                  pthread_join(ths[i], NULL);
              }

              this->CONFIG_PORT = port;
              this->CONFIG_COUNT_THREADS = nthreads;

              return 0;
        }
        // ----------------------------------------------------------------------------------------------
        void* HTTPServer::Dispatch(void *arg)
        {
              event_base_dispatch((struct event_base*)arg);
              return NULL;
        }

        // ----------------------------------------------------------------------------------------------
        void HTTPServer::GenericHandler(struct evhttp_request *req, void *arg)
        {
              ((HTTPServer*)arg)->ProcessRequest(req);
        }

        // ----------------------------------------------------------------------------------------------
        bool HTTPServer::HttpParseContentRangeHeader(struct evhttp_request *_req, int64_t *rangefirst, int64_t *rangelast, int *replycode, int64_t filesize)
        {
            struct evkeyvalq *reqheaders = evhttp_request_get_input_headers(_req);
            //struct evkeyvalq *repheaders = evhttp_request_get_output_headers(_req);
            const char *contentrangecstr = evhttp_find_header(reqheaders, "Range");

            if (contentrangecstr == NULL)
            {
                *rangefirst = -1;
                *rangelast  = -1;
                *replycode  = 200;
                return true;
            }

            std::string range = contentrangecstr;

            printf("range: %s \n", range.c_str());

            // Handle RANGE query
            bool bad = false;
            unsigned int idx = range.find("=");

            if (idx == std::string::npos)
            {
                return false;
            }

            std::string seek = range.substr(idx + 1);

            //printf("%s @%i http range request spec %s\n",tintstr(),req->id, seek.c_str() );

            if (seek.find(",") != std::string::npos)
            {
                    // - Range header contains set, not supported at the moment
                    bad = true;
            }
            else
            {
                    // Determine first and last bytes of requested range
                    idx = seek.find("-");

                    //printf("%s @%i http range request idx %d\n", tintstr(),req->id, idx );

                    if (idx == std::string::npos)
                    {
                        return false;
                    }

                    if (idx == 0)
                    {
                        *rangefirst = -1;  // -444 format
                    }
                    else
                    {
                        printf("sscanf: %s\n", seek.substr(0, idx).c_str());
                        sscanf(seek.substr(0, idx).c_str(), "%lld", rangefirst);
                    }

                    //printf("%s @%i http range request first %s %lld\n", tintstr(),req->id, seek.substr(0,idx).c_str(), *rangefirst );

                    if (idx == seek.length() - 1)
                    {
                        *rangelast = -1;
                    }
                    else
                    {
                        // 444- format
                        sscanf("%lld", seek.substr(idx+1).c_str(), rangelast);
                    }

                    //dprintf("%s @%i http range request last %s %lld\n", tintstr(),req->id, seek.substr(idx+1).c_str(), *rangelast );

                    // Check sanity of range request
                    if (filesize == -1)
                    {
                        bad = true;  // - No length (live)
                    }
                    else if (*rangefirst == -1 && *rangelast == -1)
                    {
                        bad = true;  // - Invalid input
                    }
                    else if (*rangefirst >= (int64_t)filesize)
                    {
                        bad = true;
                    }
                    else if (*rangelast >= (int64_t)filesize)
                    {
                            if (*rangefirst == -1)
                            {
                                // If the entity is shorter than the specified
                                // suffix-length, the entire entity-body is used.
                                *rangelast = filesize-1;
                            }
                            else
                            {
                                bad = true;
                            }
                    }
            }

            if (bad)
            {
                // Send 416 - Requested Range not satisfiable
                //std::ostringstream cross;
                //if (filesize == -1)
                //    cross << "bytes */*";
                //else
                //    cross << "bytes */" << filesize;
                //evhttp_add_header(repheaders, "Content-Range", cross.str().c_str() );
                //evhttp_send_error(_req, 416, "Malformed range specification");*/

                *replycode = 416;
                return false;
            }

            // Convert wildcards into actual values
            if (*rangefirst != -1 && *rangelast == -1)
            {
                // "100-" : byte 100 and further
                *rangelast = filesize - 1;
            }
            else if (*rangefirst == -1 && *rangelast != -1)
            {
                // "-100" = last 100 bytes
                *rangefirst = filesize - *rangelast;
                *rangelast = filesize - 1;
            }

            // Generate header
            /*std::ostringstream cross;
            cross << "bytes " << *rangefirst << "-" << *rangelast << "/" << filesize;
            evhttp_add_header(repheaders, "Content-Range", cross.str().c_str() );*/

            // Reply is sent when content is avail
            *replycode = 206;

            //dprintf("%s @%i http valid range %lld-%lld\n",tintstr(),req->id,*rangefirst,*rangelast );

            return true;
        }
        // ----------------------------------------------------------------------------------------------
        void HTTPServer::ProcessRequest(struct evhttp_request *req)
        {
              //sleep(1);
              struct evbuffer *buf = evbuffer_new();
              const char* accept_encoding = evhttp_find_header(req->input_headers, "accept-encoding");
              bool accept_deflate = accept_encoding && strstr(accept_encoding, "deflate");

              const char *contentrangecstr = evhttp_find_header(req->input_headers, "Range");
              bool range_file = false;

              if (! (contentrangecstr == NULL))
              {
                  range_file = true;
              }

              /*if(accept_encoding && strstr(accept_encoding, "deflate"))
              {
                  accept_deflate = true;
              }*/

              if (buf == NULL)
              { return; }

              string path   = this->CONFIG_MAIN_OFFSET_PATH;
                     path  += evhttp_request_uri(req);

              path = urlDecode(path);

              bool _file_exists = false;
              unsigned int _file_size = 0;
              unsigned long _file_time_last_modified = 0;

              struct stat b;

              if( stat(path.c_str(), &b) == 0 )
              {
                  _file_exists = true;

                  _file_size = b.st_size;
                  _file_time_last_modified = b.st_mtime;
              }

              if(range_file == false && this->CONFIG_USE_CACHE && cache__is_exists(path) )
              {
                    CacheFile cf = map_cache_file[path];

                    if( _file_exists && _file_time_last_modified == cf.file_time_last_modified )
                    {
                        // find in cache and send out
                        pthread_mutex_lock(&lock_cache);

                        if(cache__is_exists(path))
                        {
                            struct evbuffer *c_buf = evbuffer_new();

                            evhttp_add_header(req->output_headers, "Content-Type", cf.content_type.c_str());

                            if(cf.is_compressed)
                            {
                                evhttp_add_header(req->output_headers, "Content-Encoding", "gzip");
                            }

                            evbuffer_add(c_buf, cf.buffer, cf.len_buffer);

                            evhttp_add_header(req->output_headers, "Accept-Ranges", "bytes" );
                            //evhttp_add_header(req->output_headers, "Connection", "close");
                            evhttp_add_header(req->output_headers, "Connection", "keep-alive" );
                            evhttp_add_header(req->output_headers, "Keep-Alive", "timeout=15" );
                            evhttp_add_header(req->output_headers, "Server", this->CONFIG_SERVER_NAME.c_str());
                            evhttp_send_reply(req, HTTP_OK, "OK", c_buf);

                            evbuffer_free(buf);

                            map_cache_file[path].time_access_cache = time(NULL);

                            //printf("cache size: %u; len: %u KB;\n", map_cache_file.size(), (int)(total_size_cache_in_memory/1024) );
                            //printf("-- cache: %u %u\n", reinterpret_cast<std::size_t>(cf.buffer), cf.len_buffer);

                            pthread_mutex_unlock(&lock_cache);
                            return;
                        }

                        pthread_mutex_unlock(&lock_cache);
                    }
                    else
                    {
                        // remove from cache
                        pthread_mutex_lock(&lock_cache);

                        cache__remove(path);

                        pthread_mutex_unlock(&lock_cache);
                    }
              }

              //printf("paht: %s\n", path.c_str());

              bool is_dir = is_directory(path);
              string ext  = path.substr(path.find_last_of(".") + 1);

              FILE *fp = NULL;
              CacheFile _tmpCacheFile;

              if( (! is_dir) && _file_exists)
              {
                  fp = fopen(path.c_str(), "rb");
              }

              if(fp != NULL)
              {
                    bool _compress_ok = false;

                    //fseek(fp, 0, SEEK_SET);
                    //int64_t _file_size = ftell(fp);

                    if(
                           this->CONFIG_EXT_LIST_COMPRESS_FILE.find(ext) != std::string::npos
                        && accept_deflate == true
                        && _file_size < this->CONFIG_MINIMAL_SIZE_COMPRESS_FILE)
                    {
                        /// RUN COMRPESS

                        char buffer[5024] = "";
                        int num_read = 0;

                        while(true)
                        {
                            num_read = fread(buffer, 1, 5024, fp);

                            if(num_read == 0)
                            { break; }

                            evbuffer_add(buf, buffer, num_read);
                        }

                        int state;
                        struct evbuffer *out = evbuffer_new();
                        struct evbuffer_iovec iovec[1];
                        void * content_ptr = evbuffer_pullup (buf, -1);
                        const size_t content_len = evbuffer_get_length (buf);

                        z_stream stream;
                        stream.zalloc = (alloc_func) Z_NULL;
                        stream.zfree = (free_func) Z_NULL;
                        stream.opaque = (voidpf) Z_NULL;

                        deflateInit2 (&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15+16, 8, Z_DEFAULT_STRATEGY);

                        stream.next_in = (Bytef *)content_ptr;
                        stream.avail_in = content_len;

                        /* allocate space for the raw data and call deflate () just once --
                         * we won't use the deflated data if it's longer than the raw data,
                         * so it's okay to let deflate () run out of output buffer space */
                        evbuffer_reserve_space (out, content_len, iovec, 1);
                        stream.next_out = (Bytef *)iovec[0].iov_base;
                        stream.avail_out = iovec[0].iov_len;
                        state = deflate (&stream, Z_FINISH);

                        if (state == Z_STREAM_END)
                        {
                            iovec[0].iov_len -= stream.avail_out;

                            /*evhttp_add_header (req->output_headers,
                                               "Content-Encoding", "gzip");*/
                        }
                        else
                        {
                            memcpy(iovec[0].iov_base, content_ptr, content_len);
                            iovec[0].iov_len = content_len;
                        }

                        evbuffer_commit_space (out, iovec, 1);
                        deflateReset (&stream);

                        evbuffer_free (buf);
                        buf = out;

                        _compress_ok = true;

                        /*
                        evbuffer_free(buf);
                        fseek(fp, 0, SEEK_SET);
                        buf = evbuffer_new();
                        */
                    }

                    if(_compress_ok == false)
                    {
                            int64_t _pos_first = -1, _pos_last = -1;
                            int _r_code = 0;
                            bool _res_parse = this->HttpParseContentRangeHeader(req, &_pos_first, &_pos_last, &_r_code, _file_size);

                            if(_res_parse && _r_code == 206)
                            {
                                //printf("_res_parse:  %lld %lld %lld\n", _pos_first, _pos_last, _file_size);
                                fseek(fp, _pos_first, SEEK_SET);
                            }
                            else
                            {
                                fseek(fp, 0, SEEK_SET);
                            }

                            char buffer[5024] = "";
                            int num_read;

                            while(true)
                            {
                                num_read = fread(buffer, 1, 5024, fp);

                                if(num_read == 0)
                                { break; }

                                evbuffer_add(buf, buffer, num_read);
                            }

                            if(_res_parse && _r_code == 206)
                            {
                                string _bytes = "bytes ";
                                char _tmp_str[50];
                                snprintf(_tmp_str, 50, "%lld-%lld/%u", _pos_first, _pos_last, _file_size);

                                _bytes += _tmp_str;

                                evhttp_add_header(req->output_headers, "Content-Range", _bytes.c_str() );
                                evhttp_send_reply(req, 206, "Partial Content", buf);
                                return;
                            }
                    }

                    fclose(fp);

                    bool flag = false;

                    if(_compress_ok)
                    {
                        evhttp_add_header(req->output_headers, "Content-Encoding", "gzip");
                    }

                    for (map<string, string>::iterator p = this->ext_types.begin(); p != this->ext_types.end(); ++p )
                    {
                        if(p->first.compare(ext) == 0)
                        {
                            evhttp_add_header(req->output_headers, "Content-Type", p->second.c_str());

                            if(range_file == false && this->CONFIG_USE_CACHE)
                            {
                                _tmpCacheFile.content_type = p->second;
                            }
                            //printf("Content-Type: %s\n", p->second.c_str());
                            flag = true;
                            break;
                        }
                    }

                    if(flag == false) // set default header - "Content-Type"
                    {
                        printf("not ext found\n");
                        evhttp_add_header(req->output_headers, "Content-Type", "application/octet-stream");

                        if(range_file == false && this->CONFIG_USE_CACHE)
                        {
                            _tmpCacheFile.content_type = "application/octet-stream";
                        }
                    }

                    evhttp_add_header(req->output_headers, "Accept-Ranges", "bytes" );
                    //evhttp_add_header(req->output_headers, "Connection", "close");
                    evhttp_add_header(req->output_headers, "Connection", "keep-alive" );
                    evhttp_add_header(req->output_headers, "Keep-Alive", "timeout=15" );
                    evhttp_add_header(req->output_headers, "Server", this->CONFIG_SERVER_NAME.c_str());


                    unsigned int len = evbuffer_get_length(buf);
                    //printf("len buf: %u\n", len);

                    pthread_mutex_lock(&lock_cache);

                    if(   range_file == false
                       && this->CONFIG_USE_CACHE
                       && cache__is_file_added(len, this->CONFIG_CACHE_SIZE)
                       && ! cache__is_exists(path)
                      )
                    {
                        _tmpCacheFile.buffer = malloc(len); /// MALLOC
                        _tmpCacheFile.len_buffer = len;
                        _tmpCacheFile.is_compressed = _compress_ok;
                        _tmpCacheFile.file_time_last_modified = _file_time_last_modified;
                        _tmpCacheFile.time_access_cache = time(NULL);

                        evbuffer_copyout(buf, _tmpCacheFile.buffer, len);

                        //printf(">> add in cache: %s\n", path.c_str());

                        cahce__add_in_cache(path, _tmpCacheFile, this->CONFIG_CACHE_SIZE);
                    }
                    else
                    {
                        //printf("no add in cache\n");
                    }

                    pthread_mutex_unlock(&lock_cache);

                    evhttp_send_reply(req, HTTP_OK, "OK", buf);
              }
              else
              {
                  evbuffer_add_printf(buf, "<html><body>Requested: %s\n</body></html>", evhttp_request_uri(req));

                  evhttp_add_header(req->output_headers, "Server", this->CONFIG_SERVER_NAME.c_str());
                  evhttp_add_header(req->output_headers, "Content-Type", "text/html; charset=utf-8");
                  evhttp_add_header(req->output_headers, "Connection", "close");

                  evhttp_send_reply(req, HTTP_OK, "OK", buf);
              }

              evbuffer_free(buf);
        }

    }
}

int main()
{
    int port = 5050;

    if(file_exists("config.ini"))
    {
        INIReader reader("config.ini");

        port = reader.GetInteger("main", "server_port", 5050);
    }

    servers::util::HTTPServer s;
    s.serv(port, 10);
}
