#import "ViewController.h"
#include <stdio.h>
#include "fun.h"
#include "async_wake.h"
#include "bootstrap.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
  [super viewDidLoad];
  // Do any additional setup after loading the view, typically from a nib.
}


- (void)didReceiveMemoryWarning {
  printf("******* received memory warning! ***********\n");
  [super didReceiveMemoryWarning];
  // Dispose of any resources that can be recreated.
}

- (IBAction)pwnTUI:(UIButton *)sender {
    sender.enabled = NO;

    mach_port_t tfp0 = get_tfp0();

    if (tfp0 != MACH_PORT_NULL && let_the_fun_begin(tfp0) == 0) {
        self.sshdBtn.enabled = YES;
        self.suicideBtn.enabled = YES;
    } else {
        [sender setTitleColor:[UIColor redColor] forState:UIControlStateNormal];
        [sender setTitleColor:[UIColor redColor] forState:UIControlStateDisabled];
    }
}

- (IBAction)sshdTUI:(UIButton *)sender {
    // Thx Coolstar for fixing my shit :)
    untar(resourceInBundle("binpack.tar"), "/" BOOTSTRAP_PREFIX);

    printf("Dropbear would be up soon\n");

    const char *environ[] = {
        "BOOTSTRAP_PREFIX=/"BOOTSTRAP_PREFIX"",
        "PATH=/"BOOTSTRAP_PREFIX"/usr/local/bin:/"BOOTSTRAP_PREFIX"/usr/sbin:/"BOOTSTRAP_PREFIX"/usr/bin:/"BOOTSTRAP_PREFIX"/sbin:/"BOOTSTRAP_PREFIX"/bin:/bin:/usr/bin:/sbin",
        "PS1=\\h:\\w \\u\\$ ",
        NULL
    };

    const char *dbear = "/" BOOTSTRAP_PREFIX "/usr/local/bin/dropbear";
    int rv = startprog(STARTPROG_WAIT|STARTPROG_EMPOWER, dbear, (const char*[]){ dbear, "-E", "-m", "-F", "-S", "/" BOOTSTRAP_PREFIX, "-p", "2222", NULL }, environ);

    if (rv == 0) {
        sender.enabled = NO;
    } else {
        [sender setTitleColor:[UIColor redColor] forState:UIControlStateNormal];
        [sender setTitleColor:[UIColor redColor] forState:UIControlStateDisabled];
    }
}

- (IBAction)suicideTUI:(UIButton *)sender {
    sender.enabled = NO;
    setuid(501);
    kill(getpid(), SIGKILL);
}

@end
