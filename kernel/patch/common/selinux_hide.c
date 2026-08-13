#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <syscall.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/random.h>
#include <kputils.h>
#include <asm/current.h>
#include <linux/mm.h>
#include <hook.h>


struct file{};

typedef ssize_t (*sel_write_access)(struct file *file, char *buf, size_t size);
typedef ssize_t (*sel_write_context)(struct file *file, char *buf, size_t size);
typedef int (*selinux_setprocattr)(struct task_struct *p,char *name, void *value, size_t size);
sel_write_access ori_sel_write_access,back_sel_write_access;
sel_write_context ori_sel_write_context,back_sel_write_context;
selinux_setprocattr ori_selinux_setprocattr,back_selinux_setprocattr;



ssize_t hk_sel_write_context(struct file *file, char *buf, size_t size){

    uid_t uid = current_uid();
    if(uid < 10000){
        return back_sel_write_context(file,buf,size);
    }
    char tmp[64];
    if (strstr(buf, "magisk")) {
        return -22;
    }
    if (strstr(buf, "ksu")) {
        return -22;
    }
    if(strstr(buf,"system_server") && strstr(buf,"2000000")){
        return -22;
    }
    if(strstr(buf,"lsposed")){
        return -22;
    }
    if(strstr(buf,"adb_data_file")){
        return -22;
    }
    if(strstr(buf,"fsck_untrusted")){
        return -22;
    }
    // 默认允许
    return back_sel_write_context(file,buf,size);
}
ssize_t hk_sel_write_access(struct file *file, char *buf, size_t size){

    uid_t uid = current_uid();
    if(uid < 10000){
        return back_sel_write_access(file,buf,size);
    }
    if (strstr(buf, "magisk")) {
        return -22;
    }
    if (strstr(buf, "ksu")) {
        return -22;
    }
    if(strstr(buf,"system_server") && strstr(buf,"2000000")){
        return -22;
    }
    if(strstr(buf,"lsposed")){
        return -22;
    }
    if(strstr(buf,"adb_data_file")){
        return -22;
    }
    if(strstr(buf,"fsck_untrusted")){
        return -22;
    }
    if(strstr(buf,"dex2oat_exec") && strstr(buf,"2000000")){
        return -22;
    }

    // 默认允许
    return back_sel_write_access(file,buf,size);
}

int hk_selinux_setprocattr(struct task_struct *p,char *name, void *value, size_t size){
    uid_t uid = current_uid();
    if(uid < 10000){
        return back_selinux_setprocattr(p,name,value,size);
    }
    if(strstr(name,"magisk")){
        return -22;
    }
    return back_selinux_setprocattr(p,name,value,size);
}

int selinux_hide_enable()
{
    // ori_sel_write_access = (void*)kallsyms_lookup_name("sel_write_access");
    // ori_sel_write_context = (void*)kallsyms_lookup_name("sel_write_context");
    // ori_selinux_setprocattr = (void*)kallsyms_lookup_name("selinux_setprocattr");
    // hook_err_t err = hook(ori_sel_write_access,hk_sel_write_access,(void**)&back_sel_write_access);
    // if(err){
    //     pr_info("selinux-hide hook err:%d\n",err);
    // }
    // hook_err_t err1 = hook(ori_sel_write_context,hk_sel_write_context,(void**)&back_sel_write_context);
    // if(err1){
    //     pr_info("selinux-hide hook err:%d\n",err1);
    // }
    // hook_err_t err2 = hook(ori_selinux_setprocattr,hk_selinux_setprocattr,(void**)&back_selinux_setprocattr);
    // if(err2){
    //     pr_info("selinux-hide hook err:%d\n",err2);
    // }
    // pr_info("selinux-hide: %p,%p\n");
    return 1;
}

int selinux_hide_disable()
{
    // pr_info("selinux-hide: exit selinux hide\n");
    // unhook(ori_sel_write_access);
    // unhook(ori_sel_write_context);
    // unhook(ori_selinux_setprocattr);
    // pr_info("selinux-hide: uninstall hook success");
    return 1;
}
