
#include <iostream>
#include <gtest/gtest.h>
#include "client.h"
#include "server.h"
std::vector<std::string> pending_trxs;
void  show_pending_transactions()
{
    std::cout << std::string(20, '*') << std::endl;
    for (const auto& trx : pending_trxs)
        std::cout << trx << std::endl;
    std::cout << std::string(20, '*') << std::endl;
}
void show_wallets(const Server& server) {
    std::cout << std::string(20, '*') << std::endl;
    for (const auto& [client_ptr, wallet] : server.clients) {
        std::cout << client_ptr->get_id() << " : " << wallet << std::endl;
    }
    std::cout << std::string(20, '*') << std::endl;
}

int main(int argc, char **argv)
{
    if (false) // make false to run unit-tests
    {
        Server server{};
        auto bryan{ server.add_client("bryan") };
        Client const* p{ bryan.get() };
        std::string signature{ p->sign("mydata") };
        bool flag = crypto::verifySignature(p->get_publickey(), "mydata", signature);
        std::cout << signature<<std::endl;
        if (flag) std::cout << "1";
        else std::cout << "0";
        return 0;
    }
    else
    {
        ::testing::InitGoogleTest(&argc, argv);
        std::cout << "RUNNING TESTS ..." << std::endl;
        int ret{RUN_ALL_TESTS()};
        if (!ret)
            std::cout << "<<<SUCCESS>>>" << std::endl;
        else
            std::cout << "FAILED" << std::endl;
    }
    return 0;   
}