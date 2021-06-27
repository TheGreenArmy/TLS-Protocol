#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/ssl.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/md5.h>
#include <sys/types.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>

#include <stdio.h>
#include <math.h>
#include <sys/time.h>

using namespace std;

#define PORT_ADDRESS 	9034
#define TLS_VERSION 	"1.3"
#define KEY_LENGTH  2048
#define PUB_EXP     3
#define PRINT_KEYS
#define WRITE_TO_FILE
#define MAX_LENGTH 1024

string sha256(const string str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

struct server_hello
{
	int random_number;
	char protcol_version[4] = TLS_VERSION;
	char public_key[2048];
	char private_key[2048];
};

struct client_hello
{
	int random_number;
	char protcol_version[4] = TLS_VERSION;
	char public_key[2048];
	char private_key[2048];
};

struct rsa_encrpyted_message
{
	char msg[2048];
};

struct server_certification
{
	char  hash[2048];
	char  data[2048];
};

int main() {

	int sockid;
	int newfd;
	int enable = 1;
	
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	
	struct sockaddr_in serverAddress;
	struct sockaddr_in clientAddress;
	struct client_hello client_hello_msg;
	struct server_hello server_hello_msg;
	struct rsa_encrpyted_message rsa_msg;
	struct server_certification server_certf;
	
    size_t pri_len;            // Length of private key
    size_t pub_len;            // Length of public key
    socklen_t client_address_len;
    char   *pri_key;           // Private key
    char   *pub_key;           // Public key
    char   encrypt[2048];     // Encrypted message
    char   decrypt[2048];    // Decrypted message
    char   *err;               // Buffer for any error messages
    char   server_done[] = "SERVER_HELLO_DONE";
    unsigned char md5_digest[MD5_DIGEST_LENGTH];
    struct timeval begin, end;
    gettimeofday(&begin, 0);
    
    
    printf("Generating RSA (%d bits) keypair...\n", KEY_LENGTH);
    fflush(stdout);
    
    RSA *server_keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);   
	RSA *client_keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);
	
    // To get the C-string PEM form:
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());
    BIO *client_pri = BIO_new(BIO_s_mem());
    BIO *client_pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, server_keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, server_keypair);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = (char*)malloc(pri_len + 1);
    pub_key = (char*)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);
    
    BIO_write(pri, pri_key, KEY_LENGTH);
    BIO_write(pub, pub_key, KEY_LENGTH);

    PEM_read_bio_RSAPrivateKey(pri, &server_keypair, NULL, NULL);
    PEM_read_bio_RSAPublicKey(pub, &server_keypair, NULL, NULL);


	server_hello_msg.random_number = 11;
	memcpy(server_hello_msg.public_key, (const char*) pub_key,KEY_LENGTH);
	memcpy(server_hello_msg.private_key, (const char*) pri_key,KEY_LENGTH);

	memset(&serverAddress,0,sizeof(serverAddress));
	memset(&clientAddress,0,sizeof(clientAddress));

	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(PORT_ADDRESS);
	serverAddress.sin_addr.s_addr = INADDR_ANY;

	if(-1 == (sockid = socket(PF_INET,SOCK_STREAM,0)))
	{
		printf("Creating socket gives error!!!\n");
	}

	if (setsockopt(sockid, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
	{
    	perror("setsockopt(SO_REUSEADDR) failed");
	}

	if(-1 == bind(sockid,(struct sockaddr*)&serverAddress,sizeof(serverAddress)))
	{
		printf("Binding gives error!!!\n");
	}
	
	if(listen(sockid,10) < 0)
	{
		printf("Listening gives error!!!\n");
	}
	
	client_address_len = sizeof(clientAddress);
	newfd = accept(sockid,(struct sockaddr *)&clientAddress,&client_address_len);
	recv(newfd,(void*)&client_hello_msg,sizeof(client_hello_msg),0);
	
	cout << "\nServer receives server's HELLO and key exhange messages" << endl;

	BIO_write(client_pri, client_hello_msg.private_key, KEY_LENGTH);
    BIO_write(client_pub, client_hello_msg.public_key, KEY_LENGTH);

    PEM_read_bio_RSAPrivateKey(client_pri, &client_keypair, NULL, NULL);
    PEM_read_bio_RSAPublicKey(client_pub, &client_keypair, NULL, NULL);

	sprintf(server_certf.data,"%d%d%s", server_hello_msg.random_number, client_hello_msg.random_number,server_hello_msg.public_key);
	const string str = server_certf.data;
	mempcpy(server_certf.hash,sha256(str).c_str(),KEY_LENGTH);
	

    int encrypt_len;
    err = (char*)malloc(130);
    if((encrypt_len = RSA_private_encrypt(256, (unsigned char*)server_certf.hash, (unsigned char*)encrypt,
        server_keypair, RSA_NO_PADDING)) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
    }
	
    memcpy(server_certf.hash, (const char*) encrypt,encrypt_len);
    
    cout << "\nServer sends its HELLO and key exhange messages" << endl;	
	send(newfd,&server_hello_msg,sizeof(server_hello_msg),0);
	send(newfd,&server_certf,sizeof(server_certf),0);
	cout << "\nServer:Requested server certification is send" << endl;
	send(newfd,server_done,sizeof(server_done),0);

	recv(newfd,(void*)&rsa_msg,sizeof(rsa_msg),0);
	memcpy(encrypt,rsa_msg.msg,256);

	BIO_write(pub, pub_key, KEY_LENGTH);
	
	PEM_read_bio_RSAPublicKey(pub, &server_keypair, NULL, NULL);
	
    err = (char*)malloc(130);
    if(RSA_private_decrypt(256, (unsigned char*)encrypt, (unsigned char*)decrypt,
                           client_keypair, RSA_PKCS1_OAEP_PADDING) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);
    }
    
    cout << "\nServer:Received pre-master secret =>" << decrypt << endl;
    
    
    MD5((const unsigned char*)decrypt,48,(unsigned char*)&md5_digest);
    
    cout << "\nServer:Computed Master Secret =>" << md5_digest << endl;
    
	gettimeofday(&end, 0);
	long seconds = end.tv_sec - begin.tv_sec;
	long microseconds = end.tv_usec - begin.tv_usec;
	double elapsed = seconds + microseconds*1e-6;
	printf("\nTime measured: %.3f seconds.\n", elapsed);


    return 0;
}
