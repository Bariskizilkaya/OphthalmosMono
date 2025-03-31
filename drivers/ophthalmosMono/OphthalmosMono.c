#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>

static struct kprobe kp;

static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    printk(KERN_INFO "Hooked function: %s\n", p->symbol_name);
    return 0;
}

static int __init kprobe_init(void) {
    kp.symbol_name = "do_sys_open";  // Change this to the function you want to hook
    kp.pre_handler = handler_pre;

    if (register_kprobe(&kp) < 0) {
        printk(KERN_ERR "Failed to register kprobe\n");
        return -1;
    }
    printk(KERN_INFO "Kprobe registered for %s\n", kp.symbol_name);
    return 0;
}

static void __exit kprobe_exit(void) {
    unregister_kprobe(&kp);
    printk(KERN_INFO "Kprobe unregistered\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel function hooking using kprobes");
