#include <iostream>
#include <string>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <fstream>
#include <ctime>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <regex>


std::string getTimestamp() {
    std::time_t now = std::time(nullptr);
    std::tm* timeinfo = std::localtime(&now);

    char buffer[80];
    std::strftime(buffer, sizeof(buffer), "%Y_%m_%d_%H_%M", timeinfo);

    return std::string(buffer);
}

int main() {
  // OpenSSL inicializálása
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  // P12 tanúsítvány betöltése
  std::string p12_file = "k.p12";
  std::string p12_password = "BLZS2910";
  PKCS12* p12 = NULL;
  FILE* p12_file_ptr = fopen(p12_file.c_str(), "rb");
  if (!p12_file_ptr) {
    std::cerr << "Hiba a P12 fájl megnyitásakor" << std::endl;
    return 1;
  }
  p12 = d2i_PKCS12_fp(p12_file_ptr, NULL);
  fclose(p12_file_ptr);
  if (!p12) {
    std::cerr << "Hiba a P12 tanúsítvány betöltésekor" << std::endl;
    ERR_print_errors_fp(stderr);
    return 1;
  }

  // PKCS12 objektumból kulcs és tanúsítvány kinyerése
  EVP_PKEY* private_key = NULL;
  X509* certificate = NULL;
  if (!PKCS12_parse(p12, p12_password.c_str(), &private_key, &certificate, NULL)) {
    std::cerr << "Hiba a P12 objektumból kulcs és tanúsítvány kinyerésekor" << std::endl;
    ERR_print_errors_fp(stderr);
    PKCS12_free(p12);
    return 1;
  }
  PKCS12_free(p12);

  // SSL környezet létrehozása
  SSL_CTX* ssl_ctx = SSL_CTX_new(SSLv23_client_method());

  // Privát kulcs és tanúsítvány beállítása az SSL környezetben
  if (SSL_CTX_use_certificate(ssl_ctx, certificate) != 1) {
    std::cerr << "Hiba a tanúsítvány beállításakor" << std::endl;
    ERR_print_errors_fp(stderr);
    X509_free(certificate);
    EVP_PKEY_free(private_key);
    SSL_CTX_free(ssl_ctx);
    return 1;
  }
  if (SSL_CTX_use_PrivateKey(ssl_ctx, private_key) != 1) {
    std::cerr << "Hiba a privát kulcs beállításakor" << std::endl;
    ERR_print_errors_fp(stderr);
    X509_free(certificate);
    EVP_PKEY_free(private_key);
    SSL_CTX_free(ssl_ctx);
    return 1;
  }
  X509_free(certificate);
  EVP_PKEY_free(private_key);

  // SSL értelmező létrehozása
  SSL* ssl = SSL_new(ssl_ctx);

  // Socket létrehozása és csatlakozás az SSL értelmezőhöz
  BIO* bio = BIO_new_ssl_connect(ssl_ctx);
  BIO_set_conn_hostname(bio, "www4.takarnet.hu:https");
  if (BIO_do_connect(bio) <= 0) {
    std::cerr << "Hiba a csatlakozás során" << std::endl;
    ERR_print_errors_fp(stderr);
    return 1;
  }

  // GET kérés elküldése
  std::string request = "GET /tknet/digitalis_teljes5_p.hrsz_s1?sid=030320230624095350eq&kero_nev=BAL%C1ZSKA24+Kft.&kero_cim1=Csom%E1d&kero_cim2=Levente+utca+14%2FA&kero_cim3=2161&kero_anyjaneve=&kero_szulhely=&kero_szulido=&kero_szam=&talalatszam=20&helyseg=&fekves=1&hrsztol=&hrsz1tol=&hrsz2tol=&hrsz3tol=&hrszig=&hrsz1ig=&hrsz2ig=&hrsz3ig=&dijmentes=0&jogalap=&darab=1&kod=- HTTP/1.1\r\nHost: example.com\r\n\r\n";
  BIO_write(bio, request.c_str(), request.length());
    std::regex linkRegex("<a\\s+href=\"([^\"]+)\">");
    std::smatch match;

  // Válasz fogadása és kiíratása
  char response[4024];
  int len = 0;
  while ((len = BIO_read(bio, response, sizeof(response))) > 0) {
    std::cout.write(response, len);
    std::cout <<  std::endl;


    std::string html(response);
    std::regex linkRegex("<a[^>]*href=['\"]([^'\"]+)['\"][^>]*>");
    std::smatch match;

    std::string::const_iterator searchStart(html.cbegin());
    while (std::regex_search(searchStart, html.cend(), match, linkRegex)) {
        if (match.size() > 1) {
            std::cout << "link:" << match[1].str() << std::endl;
        }
        searchStart = match.suffix().first;
    }
    std::string filename = "resp_" + getTimestamp();
    std::ofstream file(filename);
    if (file.is_open()) {
        file << html;
        file.close();
        std::cout << "Data written to file: " << filename << std::endl;
    } else {
        std::cerr << "Unable to open file: " << filename << std::endl;
    }

  }

  // Bezárás és felszabadítás
  BIO_free_all(bio);
  SSL_CTX_free(ssl_ctx);

  return 0;
}
