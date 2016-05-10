#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/netfilter.h>
#include <linux/vmalloc.h>
#include <linux/icmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Denil Vira");
MODULE_DESCRIPTION("HW6 - Firewall");

static unsigned char *webServer_ip_address = "\xC0\xA8\x6C\x0A";

static char *in_interface = "eth1";

unsigned char *http_port = "\x00\x50";
unsigned char *ssh_port = "\x00\x16";


static struct nf_hook_ops nfho;   //net filter hook option struct

unsigned int my_hook(unsigned int hooknum,struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph;
    struct tcphdr *tcph;
	struct icmphdr *icmp_header;

//Start Filtering                

 	if(!skb)
		return NF_ACCEPT;
	
    iph = ip_hdr(skb);

	if ( strcmp(in->name, in_interface) == 0 )
	{
		if (iph && iph->protocol && (iph->protocol == IPPROTO_ICMP))
		{
			icmp_header = icmp_hdr(skb);
			if (icmp_header) 
			{						
				if(icmp_header->type != ICMP_ECHOREPLY)
				{
					if (iph->daddr != *(unsigned int*)webServer_ip_address)
					{
						printk(KERN_INFO "Dropped: cause: ICMP, interface: %s, dest: %pI4, src : %pI4\n", in_interface, &iph->daddr, &iph->saddr);
						return NF_DROP;
					}
				}
			}
		}

		if (iph && iph->protocol && (iph->protocol == IPPROTO_TCP))
		{
			tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);
												
			if ((tcph->dest) == *(unsigned short *)ssh_port)
			{
				printk(KERN_INFO "Dropped: cause: SSH, interface: %s, dest: %pI4, src : %pI4\n", in_interface, &iph->daddr, &iph->saddr);
				return NF_DROP;
			}
			if ((tcph->dest) == *(unsigned short *)http_port)
			{
				if (iph->daddr != *(unsigned int*)webServer_ip_address)
				{
					printk(KERN_INFO "Dropped: cause: HTTP, interface: %s, dest: %pI4, src : %pI4\n", in_interface, &iph->daddr, &iph->saddr);
					return NF_DROP;	
				}
			}
		}
	}
//End Filtering                
	return NF_ACCEPT;
}

static int init_filter_if(void)
{
	nfho.hook = (nf_hookfn *)my_hook;
	nfho.hooknum = 0;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;
	nf_register_hook (&nfho);

	return 0;
}

static int __init fire_init(void)
{
    printk(KERN_INFO "Module initailizing..\n");
    init_filter_if();
    return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void __exit fire_cleanup(void)
{
  nf_unregister_hook(&nfho);
  printk(KERN_INFO "Module cleaned\n");
}

module_init(fire_init);
module_exit(fire_cleanup);