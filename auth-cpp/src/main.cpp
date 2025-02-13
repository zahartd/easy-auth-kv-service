#include <fstream>
#include <iostream>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

#include <userver/crypto/hash.hpp>
#include <userver/easy.hpp>
#include <userver/rcu/rcu_map.hpp>
#include <userver/utest/using_namespace_userver.hpp>
#include "userver/logging/level.hpp"

#include <fmt/format.h>
#include <jwt/jwt.hpp>

std::string ReadFile(const std::string& path) {
  std::ifstream file(path);
  if (!file.is_open()) {
    throw std::runtime_error("Failed to open file: " + path);
  }
  return {std::istreambuf_iterator<char>(file),
          std::istreambuf_iterator<char>()};
}

class UserDB {
 public:
  UserDB() = default;

  void Add(const std::string& username, const std::string& hash_password) {
    map.Emplace(username, hash_password);
  }

  std::optional<std::string> Get(const std::string& username) {
    auto val_ptr = map.Get(username);
    if (!val_ptr) {
      return std::nullopt;
    }
    return *val_ptr;
  }

 private:
  rcu::RcuMap<std::string, std::string> map;
};

int main(int argc, char* argv[]) {
  std::string private_key;
  std::string public_key;
  uint16_t port = 0;
  std::vector<char*> filtered_args;
  filtered_args.push_back(argv[0]);
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--private" && i + 1 < argc) {
      private_key = ReadFile(argv[++i]);
    } else if (arg == "--public" && i + 1 < argc) {
      public_key = ReadFile(argv[++i]);
    } else if (arg == "--port" && i + 1 < argc) {
      port = std::stoi(argv[++i]);
    } else {
      filtered_args.push_back(argv[i]);
    }
  }
  argc = static_cast<int>(filtered_args.size());
  argv = filtered_args.data();

  UserDB user_db;

  easy::HttpWith<>(argc, argv)
      .Port(port)
      .LogLevel(logging::Level::kError)
      .DefaultContentType(http::content_type::kTextPlain)
      .Post(
          "/signup",
          [&private_key,
           &user_db](const server::http::HttpRequest& request) -> std::string {
            auto request_body =
                userver::formats::json::FromString(request.RequestBody());
            const auto& username = request_body["username"].As<std::string>();
            const auto& password = request_body["password"].As<std::string>();

            auto& response = request.GetHttpResponse();
            if (user_db.Get(username).has_value()) {
              response.SetStatus(userver::server::http::HttpStatus::kForbidden);
              return "User already exists";
            }

            auto hashed_password = crypto::hash::weak::Md5(password + username);
            user_db.Add(username, hashed_password);

            jwt::jwt_object token{
                jwt::params::algorithm("RS256"),
                jwt::params::secret(private_key),
                jwt::params::payload({{"username", username}})};

            response.SetCookie({"jwt", token.signature()});
            return "User registered";
          })
      .Post(
          "/login",
          [&private_key,
           &user_db](const server::http::HttpRequest& request) -> std::string {
            auto request_body =
                userver::formats::json::FromString(request.RequestBody());
            const auto& username = request_body["username"].As<std::string>();
            const auto& password = request_body["password"].As<std::string>();

            auto actual_hashed_password =
                crypto::hash::weak::Md5(password + username);

            auto& response = request.GetHttpResponse();
            if (auto expected_hashed_password = user_db.Get(username);
                !expected_hashed_password.has_value() ||
                expected_hashed_password != actual_hashed_password) {
              response.SetStatus(userver::server::http::HttpStatus::kForbidden);
              return "Invalid credentials";
            }

            jwt::jwt_object token{
                jwt::params::algorithm("RS256"),
                jwt::params::secret(private_key),
                jwt::params::payload({{"username", username}})};

            response.SetCookie({"jwt", token.signature()});
            return "Logged in";
          })
      .Get("/whoami",
           [&public_key,
            &user_db](const server::http::HttpRequest& request) -> std::string {
             auto& response = request.GetHttpResponse();
             if (!request.HasCookie("jwt")) {
               response.SetStatus(
                   userver::server::http::HttpStatus::kUnauthorized);
               return "No token provided";
             }
             const auto& token = request.GetCookie("jwt");
             try {
               auto dec_obj = jwt::decode(
                   token, jwt::params::algorithms({"RS256"}),
                   jwt::params::secret(public_key), jwt::params::verify(true));
               auto username =
                   dec_obj.payload().get_claim_value<std::string>("username");
               if (!user_db.Get(username).has_value()) {
                 response.SetStatus(
                     userver::server::http::HttpStatus::kBadRequest);
                 return "Invalid credentials";
               }
               return fmt::format("Hello, {}", username);
             } catch (...) {
               response.SetStatus(
                   userver::server::http::HttpStatus::kBadRequest);
               return "Invalid token";
             }
             return "";
           });
}
