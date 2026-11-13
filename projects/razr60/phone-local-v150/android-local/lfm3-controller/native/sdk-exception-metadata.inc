#include "sdk-exception-boundary.h"
/* Called only by the request/terminal owner, never from a signal handler.
 * The caller supplies JSON separators. Diagnostics are bounded ASCII, with
 * transformations explicitly recorded rather than presented as exact bytes. */
static void hepta_write_sdk_exception(FILE *f) {
    const HeptaSdkGenerateException *e=hepta_sdk_generate_exception();
    fprintf(f,"\"sdk_exception_boundary\":{\"enabled\":%s,\"caught\":%s,\"kind\":",
        HEPTA_SDK_EXCEPTION_BOUNDARY_ENABLED?"true":"false",e->kind?"true":"false");
    json_string(f,e->kind==1?"std_exception":e->kind==2?"other_cpp_exception":NULL);
    fputs(",\"message_ascii\":",f);json_string(f,e->kind?e->message:NULL);
    fprintf(f,",\"message_truncated\":%s,\"message_non_ascii_replaced\":%s,\"automatic_retry\":false}",
        e->message_truncated?"true":"false",e->message_non_ascii_replaced?"true":"false");
}
