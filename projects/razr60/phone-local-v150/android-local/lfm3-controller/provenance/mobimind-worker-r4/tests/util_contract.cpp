#include "probe_util.hpp"
#include "model_pins.hpp"
#include <cassert>
#include <cstdlib>
#include <iostream>

template<class F> void rejects(F f) { bool thrown=false;try{f();}catch(const std::exception&){thrown=true;}assert(thrown); }
int main() {
    assert(hash_string("")=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert(hash_string("abc")=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    HashEvidence input_evidence;
    assert(hash_string_evidence("abc",input_evidence)==hash_string("abc"));
    assert(input_evidence.complete&&input_evidence.bytes==3&&input_evidence.hardware_blocks+input_evidence.portable_blocks==1);
    assert(input_evidence.selected_hardware==hepta_sha256_runtime_sha2());
    assert(std::string(input_evidence.backend)==(input_evidence.selected_hardware?"armv8-sha2":"portable"));
    std::string million(1000000,'a');assert(hash_string(million)=="cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    assert(utf8(reinterpret_cast<const unsigned char*>(u8"中文🙂"),std::strlen(u8"中文🙂")));
    const unsigned char overlong[]={0xc0,0xaf},surrogate[]={0xed,0xa0,0x80},unfinished[]={0xe4,0xb8};
    assert(!utf8(overlong,sizeof overlong));assert(!utf8(surrogate,sizeof surrogate));assert(!utf8(unfinished,sizeof unfinished));
    assert(quote("x\"\\\n\t")=="\"x\\\"\\\\\\u000a\\u0009\"");
    std::string prompt="<|im_start|>user\n任务 <img>screen</img><|im_end|>\n<|im_start|>assistant\n";
    validate_prompt(prompt);validate_prompt(prompt.substr(0,prompt.size()-1));
    rejects([&]{validate_prompt(prompt+"x");});rejects([&]{validate_prompt(prompt+"\n");});
    rejects([&]{validate_prompt("<img>/private/file.png</img>"+prompt);});
    rejects([&]{validate_prompt("<audio>https://example.org/a</audio>"+prompt);});
    assert(image_target(1224,2992,1024)==std::make_pair(416,1024));
    rejects([]{image_target(200000,100,1024);});
    rejects([]{image_target(8192,8192,1024);});
    int ids[]={1,42,151655,-1};assert(token_ids_sha(ids,4)=="b19cd2cf8ecd9d1e65f5c15c8872df1f9948b6a31c593802cc76e41641ace8f2");
    char tmp[]="/tmp/hepta-mobi-contract-XXXXXX";char* d=::mkdtemp(tmp);assert(d);
    std::string file=std::string(d)+"/input";write_new(file,"abc");
    {BoundFile f(file,3);HashEvidence first,again;
        assert(f.hash(&first)==hash_string("abc"));assert(f.hash(&again)==hash_string("abc"));assert(f.read(3)=="abc");
        for(const auto& evidence:{first,again}){
            assert(evidence.complete&&evidence.bytes==3&&evidence.hardware_blocks+evidence.portable_blocks==1);
            assert(evidence.selected_hardware==hepta_sha256_runtime_sha2());
        }
        int fd=::open(file.c_str(),O_WRONLY);assert(fd>=0);assert(::pwrite(fd,"X",1,0)==1);::close(fd);rejects([&]{f.verify();});
        rejects([&]{f.hash(&again);});assert(!again.complete&&again.bytes==0&&again.hardware_blocks==0&&again.portable_blocks==0);}
    std::string link=std::string(d)+"/link";assert(::symlink(file.c_str(),link.c_str())==0);rejects([&]{BoundFile f(link,3);});
    rejects([&]{write_new(file,"replace");});::unlink(link.c_str());::unlink(file.c_str());::rmdir(d);
    assert(sizeof(MODEL_PINS)/sizeof(MODEL_PINS[0])==11);
    std::cout<<"util-contract: SHA256 / UTF8 / prompt-media / size / file-identity / symlink / overwrite tests passed\n";
}
