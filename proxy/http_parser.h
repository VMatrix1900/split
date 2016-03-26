class HTTPStreamParser {
 public:
  HTTPStreamParser();
  ~HTTPStreamParser();

  http::BufferedRequest request;
  http::BufferedResponse response;
  bool interested;
  std::string url;

}

ParseHTTPRequest(int id, const char *buf, int size, const char *result, int result_length, enum packet_type side);
ParseHTTPResponse(int id, const char *buf, int size, const char *result, int result_length);


