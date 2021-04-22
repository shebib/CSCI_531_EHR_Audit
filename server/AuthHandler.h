#pragma once
class AuthHandler
{
public:
  AuthHandler() {}
  bool authorize(std::string username, std::string rawpass);

private:
  ServerFileImporter sfi;
  bool readAuthInfo();



};
 