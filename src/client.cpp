#include "client.h"
#include "crypto.h"
#include "server.h"
#include<string>
Client::Client(std::string id,  Server& server) :id(std::move(id)), server(&server) {
	crypto::generate_key(this->public_key, this->private_key);
}//因为id和constserver都是常量所以不能再构造函数里进行改变只能在初始化完成
std::string Client::get_id() const{
	return this->id;
}
std::string Client::get_publickey() const{
	return this->public_key;
}
double Client::get_wallet() const{
	return server->get_wallet(id);
}
std::string Client::sign(std::string txt) const{
	std::string signature = crypto::signMessage(private_key, txt);
	std::string test = "mydata";
	std::string test_sig = crypto::signMessage(private_key, test);
	return signature;
}
bool Client::transfer_money(std::string receiver, double value) {
	std::string sender = this->get_id();
	std::string trx = sender + '-' + receiver + '-' + std::to_string(value);
	std::string signature = sign(trx);
	bool flag = this->server->add_pending_trx(trx, signature);
	return flag;
}
size_t Client::generate_nonce() {
	static std::random_device rd; 
	static std::mt19937 gen(rd()); 
	static std::uniform_int_distribution<size_t> dist(0, 1000000);
	return dist(gen);
}

