#include <isolate.h>
#include <stddef.h>

int main()
{
    isolate_config config = {};
    char *argv[3] = { "/usr/bin/echo", "Coucou", NULL };
    init(config);
    for (int i = 0; i < 10; i++)
        run(argv, config);
    cleanup(config);
}
