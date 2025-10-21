#ifndef CLIENT_H
#define CLIENT_H
#include<iostream>
#include<vector>
#include<string>
class Server; 
extern std::vector<std::string> pending_trxs;
class Client
{
public:
	Client(std::string id, Server& server);
	std::string get_id() const;
	std::string get_publickey() const;
	double get_wallet() const;
	std::string sign(std::string txt) const;
	bool transfer_money(std::string receiver, double value);
	size_t generate_nonce();
private:
	Server * const server;//����ָ��ָ����ָ�벻�ܱ䳣�����ܱ��
	const std::string id;//idΪ����
	std::string public_key;
	std::string private_key;
};
#endif //CLIENT_H