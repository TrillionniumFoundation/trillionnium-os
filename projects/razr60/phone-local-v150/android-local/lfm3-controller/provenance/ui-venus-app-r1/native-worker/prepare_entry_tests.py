#!/usr/bin/env python3
"""Prepare tests of exact C guard functions; this script does not compile/run."""
from pathlib import Path
import hashlib
import json


def extract(source, name):
    marker = "static bool " + name + "("
    if source.count(marker) != 1:
        raise ValueError("unique exact function required: " + name)
    start = source.index(marker)
    end = source.index("\n}\n", start) + 3
    return source[start:end]


def main():
    root = Path(__file__).resolve().parent
    helper = (root / "native/app-entry-guard.h").read_text()
    core = (root / "native/worker-venus.c").read_text()
    names = ["venus_app_decimal", "venus_app_take_arguments", "venus_app_status_number",
             "venus_app_status_tail", "venus_app_parent_status", "venus_app_parent_cmdline"]
    chunks = [extract(core, "utf8"), extract(core, "canonical")]
    start = helper.index("typedef struct {")
    end = helper.index("} VenusAppEntry;", start) + len("} VenusAppEntry;")
    chunks.append(helper[start:end])
    chunks.extend(extract(helper, name) for name in names)
    prefix = """#define _GNU_SOURCE 1
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#define VENUS_APP_PACKAGE "org.trillionnium.hepta.local"
/* Functions below are extracted verbatim from the actual source by the
 * preparation script, not a separate Python implementation of the rules. */
"""
    tests = r'''
static unsigned assertions;
#define CHECK(x) do { assertions++; if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);return 1;} } while(0)
int main(void){
    unsigned long value=0;
    CHECK(venus_app_decimal("10000",INT_MAX,&value)&&value==10000);
    CHECK(venus_app_decimal("2147483647",INT_MAX,&value)&&value==2147483647ul);
    CHECK(!venus_app_decimal("2147483648",INT_MAX,&value));
    CHECK(!venus_app_decimal("010000",INT_MAX,&value));
    CHECK(!venus_app_decimal("+10000",INT_MAX,&value));
    CHECK(!venus_app_decimal("10000\n",INT_MAX,&value));
    CHECK(!venus_app_decimal("",INT_MAX,&value));
    CHECK(!venus_app_decimal(NULL,INT_MAX,&value));
    const unsigned char valid_status[]="Name:\tapp\nPid:\t12345\nUid:\t12001\t12001\t12001\t12001\n";
    CHECK(venus_app_parent_status(valid_status,sizeof(valid_status)-1,12345,12001));
    CHECK(!venus_app_parent_status(valid_status,sizeof(valid_status)-1,12346,12001));
    CHECK(!venus_app_parent_status(valid_status,sizeof(valid_status)-1,12345,12002));
    CHECK(!venus_app_parent_status(valid_status,sizeof(valid_status)-2,12345,12001));
    const unsigned char mismatched_fsuid[]="Pid:\t12345\nUid:\t12001\t12001\t12001\t12002\n";
    CHECK(!venus_app_parent_status(mismatched_fsuid,sizeof(mismatched_fsuid)-1,12345,12001));
    const unsigned char repeated_pid[]="Pid:\t12345\nPid:\t12345\nUid:\t12001\t12001\t12001\t12001\n";
    CHECK(!venus_app_parent_status(repeated_pid,sizeof(repeated_pid)-1,12345,12001));
    const unsigned char missing_uid[]="Pid:\t12345\n";
    CHECK(!venus_app_parent_status(missing_uid,sizeof(missing_uid)-1,12345,12001));
    const unsigned char nul_status[]="Pid:\t12345\n\0Uid:\t12001\t12001\t12001\t12001\n";
    CHECK(!venus_app_parent_status(nul_status,sizeof(nul_status)-1,12345,12001));
    const unsigned char too_many_uids[]="Pid:\t12345\nUid:\t12001\t12001\t12001\t12001\t12001\n";
    CHECK(!venus_app_parent_status(too_many_uids,sizeof(too_many_uids)-1,12345,12001));
    unsigned char padded[99]={0};
    memcpy(padded,VENUS_APP_PACKAGE,strlen(VENUS_APP_PACKAGE));
    CHECK(venus_app_parent_cmdline(padded,sizeof(padded)));
    CHECK(venus_app_parent_cmdline(padded,strlen(VENUS_APP_PACKAGE)+1));
    CHECK(!venus_app_parent_cmdline(padded,strlen(VENUS_APP_PACKAGE)));
    padded[sizeof(padded)-1]='x';
    CHECK(!venus_app_parent_cmdline(padded,sizeof(padded)));
    const unsigned char suffixed[]=VENUS_APP_PACKAGE ":worker";
    CHECK(!venus_app_parent_cmdline(suffixed,sizeof(suffixed)));
    const unsigned char extra_argument[]=VENUS_APP_PACKAGE "\0--extra";
    CHECK(!venus_app_parent_cmdline(extra_argument,sizeof(extra_argument)));
    const unsigned char shell[]="sh";
    CHECK(!venus_app_parent_cmdline(shell,sizeof(shell)));
    char temporary[]="/tmp/hepta-ui-venus-entry-contract-XXXXXX";
    CHECK(mkdtemp(temporary)!=NULL);
    char directory[PATH_MAX];CHECK(realpath(temporary,directory)!=NULL);
    char *ok[]={"worker","--expected-app-uid","12001","--app-files-dir",directory,"--request-id","abc",NULL};
    int argc=7;VenusAppEntry entry={0};
    CHECK(venus_app_take_arguments(&argc,ok,&entry));
    CHECK(argc==3&&!strcmp(ok[1],"--request-id")&&!strcmp(ok[2],"abc")&&ok[3]==NULL);
    CHECK(entry.expected_uid==12001&&!strcmp(entry.files,directory));
    char *shell_uid[]={"worker","--expected-app-uid","2000","--app-files-dir",directory,NULL};
    argc=5;CHECK(!venus_app_take_arguments(&argc,shell_uid,&entry));
    char *low_uid[]={"worker","--expected-app-uid","9999","--app-files-dir",directory,NULL};
    argc=5;CHECK(!venus_app_take_arguments(&argc,low_uid,&entry));
    char *duplicate[]={"worker","--expected-app-uid","12001","--app-files-dir",directory,"--expected-app-uid","12001",NULL};
    argc=7;CHECK(!venus_app_take_arguments(&argc,duplicate,&entry));
    char *reordered[]={"worker","--app-files-dir",directory,"--expected-app-uid","12001",NULL};
    argc=5;CHECK(!venus_app_take_arguments(&argc,reordered,&entry));
    char noncanonical[PATH_MAX];
    int n=snprintf(noncanonical,sizeof(noncanonical),"%s/../",directory);CHECK(n>0&&(size_t)n<sizeof(noncanonical));
    char *bad_path[]={"worker","--expected-app-uid","12001","--app-files-dir",noncanonical,NULL};
    argc=5;CHECK(!venus_app_take_arguments(&argc,bad_path,&entry));
    CHECK(rmdir(temporary)==0);
    printf("{\"schema\":\"hepta.ui-venus.app-entry-contract-test.v1\",\"assertions\":%u,\"passed\":true,\"sdk_initialized\":false,\"phone_contact\":false}\n",assertions);
    return 0;
}
'''
    source = prefix + "\n\n".join(chunks) + "\n" + tests
    output = root / "tests"
    output.mkdir(exist_ok=True)
    path = output / "app_entry_contract.c"
    path.write_text(source)
    evidence = {"schema": "hepta.ui-venus.app-entry-test-source.v1",
                "generated_from_exact_actual_functions": True,
                "helper_sha256": hashlib.sha256(helper.encode()).hexdigest(),
                "original_core_sha256": hashlib.sha256(core.encode()).hexdigest(),
                "test_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                "compiled": False, "executed": False,
                "compile_after_review": "cc -std=c11 -Wall -Wextra -Werror tests/app_entry_contract.c -o tests/app_entry_contract"}
    (output / "PREPARED.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
