#include "types.h"

#include <iostream>
#include <unordered_set>

int main() {
    using namespace DPI;
    int failures = 0;
    const auto check = [&failures](bool condition, const char* message) {
        if (!condition) {
            std::cerr << "FAILED: " << message << '\n';
            ++failures;
        }
    };

    const FiveTuple first{0x0100007f, 0x0200007f, 51000, 443, 6};
    const FiveTuple same{0x0100007f, 0x0200007f, 51000, 443, 6};
    const FiveTuple different{0x0100007f, 0x0200007f, 51001, 443, 6};
    const FiveTuple reverse{0x0200007f, 0x0100007f, 443, 51000, 6};

    check(first == same, "equal five-tuples compare equal");
    check(!(first == different), "different five-tuples compare unequal");
    check(first.reverse() == reverse, "five-tuple reverse swaps endpoints");

    std::unordered_set<FiveTuple, FiveTupleHash> flows;
    flows.insert(first);
    flows.insert(same);
    flows.insert(different);
    check(flows.size() == 2, "five-tuple hash supports unordered_set");

    check(sniToAppType("www.youtube.com") == AppType::YOUTUBE, "YouTube SNI classification");
    check(sniToAppType("www.facebook.com") == AppType::FACEBOOK, "Facebook SNI classification");
    check(sniToAppType("www.instagram.com") == AppType::INSTAGRAM, "Instagram SNI classification");
    check(sniToAppType("twitter.com") == AppType::TWITTER, "Twitter SNI classification");
    check(sniToAppType("mobile.x.com") == AppType::TWITTER, "X domain SNI classification");
    check(sniToAppType("www.netflix.com") == AppType::NETFLIX, "Netflix SNI classification");
    check(sniToAppType("github.com") == AppType::GITHUB, "GitHub SNI classification");

    return failures == 0 ? 0 : 1;
}