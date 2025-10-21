#include "server.h"
#include "client.h"
Server::Server() {}
std::shared_ptr<Client> Server::add_client(std::string id) {
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(1000, 9999);//创建随机数种子
	int random_number = dis(gen);
	bool exist = false;
	for (auto& [client_ptr, wallet] : clients) {
		if (client_ptr->get_id() == id) {
			exist = true;
			break;
		}
	}//检测是否重复id
	if (exist) {
		id += std::to_string(random_number);
	}
	std::shared_ptr<Client> new_client = std::make_shared<Client>(id, *this);//创建智能Client类型指针
	clients.insert(std::make_pair(new_client, 5));//插入
	return new_client;
}
std::shared_ptr<Client> Server::get_client(std::string id) const {
	for (auto& [client_ptr, wallet] : clients) {
		if (client_ptr->get_id() == id) {
			return client_ptr;
		}
	}
	return NULL;
}
double Server::get_wallet(std::string id)  const{
	for (const auto& [client_ptr, wallet] : clients) {
		if (client_ptr->get_id() == id) {
			return wallet;
		}
	}
	throw std::logic_error("没有该id");
}
bool Server::parse_trx(std::string trx, std::string& sender, std::string& receiver, double& value) {
	sender.clear();
	receiver.clear();
	value = 0;  // ✅ 必须清空，否则会被上次调用残留字符污染

	int num = 1;
	std::string valuee = "";
	for (auto& pos : trx) {
		if (pos == '-') {
			num++;
			continue;
		}
		if (num == 1) sender += pos;
		if (num == 2) receiver += pos;
		if (num == 3) valuee += pos;
	}

	// 检查格式是否合法
	if (num != 3) throw std::runtime_error("invalid transaction format");

	value = std::stod(valuee);

	bool sender_found = false, receiver_found = false;
	for (auto& [client_ptr, wallet] : clients) {
		if (client_ptr->get_id() == sender) sender_found = true;
		if (client_ptr->get_id() == receiver) receiver_found = true;
	}

	if (!sender_found || !receiver_found) return false;
	return true;
}

bool Server::add_pending_trx(std::string trx, std::string signature) {
	std::string sender, receiver="";double value=0;
	bool flag = parse_trx(trx, sender, receiver, value);
	if (!flag) return false;
	std::shared_ptr<Client> sender_client = get_client(sender);
	bool authentic = crypto::verifySignature(sender_client->get_publickey(), trx, signature);
	if (!authentic) return false;
	if (get_wallet(sender) < value) return false;
	pending_trxs.push_back(trx);
	return true;
}
size_t Server::mine() {
	std::string sum_pending_trxs="";
	for (auto& it : pending_trxs) {
		sum_pending_trxs += it;
	}
	int rl_nonce = 0;
	while(1) {
		bool whl = false;
		for (auto& [now_client, wallet] : clients) {
			int nonce = now_client->generate_nonce();
			std::string now_sum_pending_trxs = sum_pending_trxs + std::to_string(nonce);
			std::string hash{ crypto::sha256(now_sum_pending_trxs) };
			bool flag = false;
			for (int i = 0;i < 8;i++) {
				if (hash[i] == '0' && hash[i + 1] == '0' && hash[i + 2] == '0') {
					wallet += 6.25;
					rl_nonce = nonce;
					std::cout << "Miner: " << now_client->get_id() << std::endl;
					flag = true;
					whl = true;
					break;
				}
			}
			if (flag == true) break;
		}
		if (whl == true) break;
	}
	for (auto& ok : pending_trxs) {
		std::string sender, receiver;double value = 0;
		bool flag = parse_trx(ok, sender, receiver, value);
		for (auto& [now_ptr, wallet] : clients) {
			if (now_ptr->get_id() == sender) wallet -= value;
			if (now_ptr->get_id() == receiver) wallet += value;
		}
	}
	pending_trxs.clear();
	return rl_nonce;
}