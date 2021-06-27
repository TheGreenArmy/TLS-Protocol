#include <iostream>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <sys/time.h>

#define PORT_ADDRESS 9034
#define TLS_VERSION "1.3"
#define KEY_LENGTH  2048
#define PUB_EXP     3
#define PRINT_KEYS
#define WRITE_TO_FILE
#define MAX_LENGTH 1024

using namespace std;

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

void print_certificate(X509* cert) {
	char subj[MAX_LENGTH+1];
	char issuer[MAX_LENGTH+1];
	X509_NAME_oneline(X509_get_subject_name(cert), subj, MAX_LENGTH);
	X509_NAME_oneline(X509_get_issuer_name(cert), issuer, MAX_LENGTH);
	printf("certificate: %s\n", subj);
	printf("issuer: %s\n", issuer);
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
	FILE encrypted_file;
};

struct server_certification
{
	char  hash[2048];
	char  data[2048];
};


int main() {
	
	int sockid;
	int encrypt_len;
	struct sockaddr_in serverAddress;
	struct client_hello client_hello_message;
	struct server_hello server_hello_message;
	struct rsa_encrpyted_message rsa_msg;
    
    size_t pri_len;            // Length of private key
    size_t pub_len;            // Length of public key
    char   *pri_key;           // Private key
    char   *pub_key;           // Public key
    char   encrypt[2048];     // Encrypted message
    char   decrypt[2048];    // Decrypted message
    char   hash_result[2048];
    char   *err;               // Buffer for any error messages
	char   server_done[18];
	char   pre_master_secret[46];
	char   pre_master_secret_message[48];
	unsigned char md5_digest[MD5_DIGEST_LENGTH];
	struct server_certification server_certf;    
    struct timeval begin, end;
    gettimeofday(&begin, 0);
        
    printf("Generating RSA (%d bits) keypair...", KEY_LENGTH);
    fflush(stdout);
    RSA *client_keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);  
    RSA *server_keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);

    // To get the C-string PEM form:
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    // To get the C-string PEM form:
    BIO *server_pri = BIO_new(BIO_s_mem());
    BIO *server_pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, client_keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, client_keypair);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = (char*)malloc(pri_len + 1);
    pub_key = (char*)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    //pri_key[pri_len] = '\0';
    //pub_key[pub_len] = '\0';

	client_hello_message.random_number = 5;
	memcpy(client_hello_message.public_key, (const char*) pub_key,KEY_LENGTH);
	memcpy(client_hello_message.private_key, (const char*) pri_key,KEY_LENGTH);
	
	memset(&serverAddress, 0, sizeof(serverAddress));
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(PORT_ADDRESS);
	serverAddress.sin_addr.s_addr = INADDR_ANY;	
	
	if(-1 == (sockid = socket(PF_INET,SOCK_STREAM,0)))
	{
		printf("Cannot open socket!!!\n");
		exit(0);
	}

	if(-1 == connect(sockid,(struct sockaddr*)&serverAddress,sizeof(serverAddress)))
	{
		printf("Connection failed!!\n");
		exit(0);
	}

	// Hello and key exchange messages are sent in same struct
	cout << "Client sends its HELLO and key exhange messages" << endl;	
	send(sockid,&client_hello_message,sizeof(client_hello_message),0);
	
	recv(sockid,(void*)&server_hello_message,sizeof(server_hello_message),0);
	recv(sockid,(void*)&server_certf,sizeof(server_certf),0);
	cout << "\nClient receives server's HELLO and key exhange messages and certification" << endl;
	
	recv(sockid,(void*)server_done,sizeof(server_done),0);
	cout << "\n" << server_done << " message is received" << endl;
	
    BIO_write(server_pri, server_hello_message.private_key, KEY_LENGTH);
    BIO_write(server_pub, server_hello_message.public_key, KEY_LENGTH);

    PEM_read_bio_RSAPrivateKey(server_pri, &server_keypair, NULL, NULL);
    PEM_read_bio_RSAPublicKey(server_pub, &server_keypair, NULL, NULL);

    if(RSA_public_decrypt(256, (unsigned char*)server_certf.hash, (unsigned char*)decrypt,
                           server_keypair, RSA_NO_PADDING) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);
    }
    	
	const string str = server_certf.data;
	strcpy(hash_result,sha256(str).c_str());
	
	if(!strcmp (hash_result,decrypt))
	{
		cout << "\nClient:SERVER IS AUTHENTICATED SUCCESFULLY!!" << endl;
	}
	else
	{
		cout << "FAILURE!!!!\nClient:Server is no authenticated succesfully!!!" << endl;
	}
	
	RAND_bytes((unsigned char*)pre_master_secret,46);
	
	sprintf(pre_master_secret_message,"%d%d%s", 1,3,pre_master_secret);

	
	cout << "\nClient:Computed pre-master secret =>" << pre_master_secret_message << endl;
	
	
    err = (char*)malloc(130);
    if((encrypt_len = RSA_public_encrypt(strlen(pre_master_secret_message)+1, (unsigned char*)pre_master_secret_message, (unsigned char*)encrypt,
                                         client_keypair, RSA_PKCS1_OAEP_PADDING)) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
    }
    
    memcpy(rsa_msg.msg, (const char*) encrypt,256);    
    send(sockid,&rsa_msg,sizeof(rsa_msg),0);
		
    MD5((const unsigned char*)pre_master_secret_message,48,(unsigned char*)&md5_digest);
    
    cout << "\nClient:Computed master secret =>" << md5_digest << endl;    

	gettimeofday(&end, 0);
	long seconds = end.tv_sec - begin.tv_sec;
	long microseconds = end.tv_usec - begin.tv_usec;
	double elapsed = seconds + microseconds*1e-6;
	printf("\nTime measured: %.3f seconds.\n", elapsed);	

    return 0;
}
