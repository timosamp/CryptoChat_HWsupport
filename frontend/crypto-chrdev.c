/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-cryptodev device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int len;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	struct virtqueue *vq;
	unsigned int *syscall_type;
	int *host_fd;
	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];
	unsigned int num_out = 0, num_in = 0;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_OPEN;

	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = -1;


	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor", 
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}

	vq = crdev->vq;
	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;

	/**
	 * We need two sg lists, one for syscall_type and one to get the 
	 * file descriptor from the host.
	 **/
	/* ?? */

	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;

	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out + num_in++] = &host_fd_sg;

	spin_lock_irq(&crdev->lock);
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);

	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */

	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
	spin_unlock_irq(&crdev->lock);


	/* If host failed to open() return -ENODEV. */
	/* ?? */

	if(*host_fd < 0){
		ret = -ENODEV;
		debug("Host failed to open the file\n");
		goto fail;
	}

	debug("Leaving with fd: %d", *host_fd);

	crof->host_fd = *host_fd;

	kfree(host_fd);
	kfree(syscall_type);
		

fail:
	debug("Leaving");
	return ret;
	//return -ENODEV;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	unsigned int *syscall_type;
	unsigned int len;
	int *host_fd;
	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];
	unsigned int num_out = 0, num_in = 0;

	debug("Entering");

	
	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_CLOSE;

	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = crof->host_fd;

	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;

	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out++] = &host_fd_sg;
	/**
	 * Send data to the host.
	 **/
	spin_lock_irq(&crdev->lock);
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);

	/**
	 * Wait for the host to process our data.
	 **/
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
	spin_unlock_irq(&crdev->lock);

	debug("Leaving with fd: %d", *host_fd);

	kfree(crof);

	debug("Leaving");
	return ret;

}


static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long arg)
{
	long ret = 0;
	int err;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, host_fd_sg, ioctl_cmd_sg, session_key_sg, session_op_sg, crypt_op_sg, src_sg, iv_sg, dst_sg, ses_id_sg, host_return_val_sg,
	                   *sgs[8];
	unsigned int num_out, num_in, len;
#define MSG_LEN 100
	unsigned char *output_msg, *input_msg;
	unsigned int *syscall_type;
	unsigned char *key;
	int i, *host_fd, *host_return_val, key_len, src_len=0, iv_len;
	unsigned int *ioctl_cmd;
	struct session_op *session_op = NULL;
	unsigned char *session_key, *src, *old_src = NULL, *iv, *old_iv = NULL, *dst, *old_dst = NULL;
	struct crypt_op *crypt_op = NULL;
	u32 *ses_id;

	debug("Entering");
    //struct session_op sess;
    //struct crypt_op cryp;

	/**
	 * Allocate all common data that will be sent to the host.
	 **/
	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_IOCTL;

	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = crof->host_fd;

	debug("host_fd --> %d", *host_fd);

	ioctl_cmd = kzalloc(sizeof(*ioctl_cmd), GFP_KERNEL);
	*ioctl_cmd = cmd;

	host_return_val = kzalloc(sizeof(*host_return_val), GFP_KERNEL);
	*host_return_val = -1;

	num_out = 0;
	num_in = 0;

	/**
	 *  These are common to all ioctl commands.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	 
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out++] = &host_fd_sg;

	sg_init_one(&ioctl_cmd_sg, ioctl_cmd, sizeof(*ioctl_cmd));
	sgs[num_out++] = &ioctl_cmd_sg;
		

	/**
	 *  Add all the cmd specific sg lists.
	 **/
	
	switch (cmd) {
	case CIOCGSESSION:
		debug("CIOCGSESSION");


		session_op = kzalloc(sizeof(*session_op), GFP_KERNEL);
		if (copy_from_user(session_op, (void *)arg, sizeof(struct session_op))) {
			debug("Failed to copy from user session_op\n");
			return -EFAULT;
		}	

		debug("cipher: %d",session_op->cipher);

		key_len = session_op->keylen;
		debug("key_len: %u", key_len);

		session_key = kzalloc(key_len * sizeof(*session_key) , GFP_KERNEL);
		//memcpy(session_key, session_op->key, key_len * sizeof(*session_key));
		if (copy_from_user(session_key, session_op->key, key_len * sizeof(*session_key))) {
			debug("Failed to copy from user key\n");
			return -EFAULT;
		}	
		session_op->key = session_key;
		//session_key = session_op->key;

		sg_init_one(&session_key_sg, session_key, key_len * sizeof(*session_key));
		sgs[num_out++] = &session_key_sg;

		sg_init_one(&session_op_sg, session_op, sizeof(struct session_op));
		sgs[num_out + num_in++] = &session_op_sg;

		//key = ((struct session_op *)output_msg)->key;
		//debug("[KEY IS]:\n");
		//for (i=0; i<15; i++) {
		//	printk(KERN_DEBUG "[LETTER]:%u", key[i]);
		//}
		//debug("[END]\n");
		
		break;
	case CIOCFSESSION:
		debug("CIOCFSESSION");
		
		//memcpy(output_msg, "Hello HOST from ioctl CIOCFSESSION.", 36);
		//input_msg[0] = '\0';
		//sg_init_one(&output_msg_sg, output_msg, MSG_LEN);
		//copy_from_user(output_msg, (void *)arg, sizeof(struct session_op));
		
		ses_id = kzalloc(sizeof(*ses_id), GFP_KERNEL);
		
		if (copy_from_user(ses_id, (void *)arg, sizeof(*ses_id))) {
			debug("Failed to copy from user ses_id\n");
			return -EFAULT;
		}	
		sg_init_one(&ses_id_sg, ses_id, MSG_LEN);
		sgs[num_out++] = &ses_id_sg;

		break;
	
	case CIOCCRYPT:
		debug("CIOCCRYPT");
		
		crypt_op = kzalloc(sizeof(*crypt_op), GFP_KERNEL);
		if (copy_from_user(crypt_op, (void *)arg, sizeof(struct crypt_op))) {
			debug("Failed to copy from user crypt_op\n");
			return -EFAULT;
		}


		old_src = crypt_op->src;
		old_iv = crypt_op->iv;
		old_dst = crypt_op->dst;

		debug("Old src: %p", crypt_op->src);

		debug("Our session ses is: %u", crypt_op->ses);

		src_len = crypt_op->len;
		debug("src_len: %d", src_len);

		src = kzalloc(src_len * sizeof(*src) , GFP_KERNEL);
		//memcpy(src, crypt_op->src, src_len * sizeof(*src));
		if (copy_from_user(src, crypt_op->src, src_len * sizeof(*src))) {
			debug("failed to copy from user src\n");
			return -EFAULT;
		}
		crypt_op->src = src;

		debug("new src before: %p", crypt_op->src);

		dst = kzalloc(src_len * sizeof(*dst) , GFP_KERNEL);
		if (copy_from_user(dst, crypt_op->dst, src_len * sizeof(*src))) {
			debug("Failed to copy from user dst\n");
			return -EFAULT;
		}	
		crypt_op->dst = dst;

		iv = kzalloc(16 * sizeof(*src) , GFP_KERNEL);
		if (copy_from_user(iv, crypt_op->iv, 16 * sizeof(*src))) {
			debug("Failed to copy from user iv\n");
			return -EFAULT;
		}	
		crypt_op->iv = iv;

		debug("crypt_op->: %p", crypt_op);
		debug("crypt_op.ses: %u", crypt_op->ses);
		debug("crypt_op.len: %d", crypt_op->len);
		debug("crypt_op.op: %d", crypt_op->op);

		sg_init_one(&crypt_op_sg, crypt_op, sizeof(struct crypt_op));
		sgs[num_out++] = &crypt_op_sg;

		sg_init_one(&src_sg, src, src_len * sizeof(*src));
		sgs[num_out++] = &src_sg;

		sg_init_one(&iv_sg, iv, 16 * sizeof(*src));
		sgs[num_out++] = &iv_sg;

		sg_init_one(&dst_sg, dst, src_len * sizeof(*src));
		sgs[num_out + num_in++] = &dst_sg;

		break;

	default:
		debug("Unsupported ioctl command");

		break;
	}

	sg_init_one(&host_return_val_sg, host_return_val, sizeof(*host_return_val));
	sgs[num_out + num_in++] = &host_return_val_sg;

	spin_lock_irq(&crdev->lock);
	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	/* ?? Lock ?? */
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
	
	switch (cmd) {
	case CIOCGSESSION:
		debug("sess.ses: %u\n", session_op->ses);
		if (copy_to_user((struct session_op *)arg, session_op, sizeof(struct session_op))) {
			debug("Failed to copy to user\n");
			return -EFAULT;
		}	

		break;
//	case CIOCFSESSION:
//		return -EFAULT;
//		break;
	case CIOCCRYPT:

		
		debug("Old src: %p", old_src);
		debug("new src after: %p", crypt_op->src);
		if (copy_to_user(old_src, crypt_op->src, src_len * sizeof(*src))) {
			debug("Failed to copy to user src\n");
			return -EFAULT;
		}	

		if (copy_to_user(old_iv, crypt_op->iv, 16 * sizeof(*src))) {
			debug("Failed to copy to user iv\n");
			return -EFAULT;
		}	

      		debug("crypt_op->after: %p", crypt_op);
      		debug("src_len: %d", src_len);
		if (copy_to_user(old_dst, crypt_op->dst, src_len * sizeof(*src))) {
			debug("Failed to copy to user dst\n");
			return -EFAULT;
		}	

		crypt_op->src = old_src;
		crypt_op->iv = old_iv;
		crypt_op->dst = old_dst;

		if (copy_to_user((struct crypt_op *)arg, crypt_op, sizeof(struct crypt_op))) {
			debug("Failed to copy to user\n");
			return -EFAULT;
		}	

		break;
	default:
		debug("Unsupported ioctl command");

		break;
	}
	spin_unlock_irq(&crdev->lock);
//	debug("We said: '%s'", output_msg);
//	debug("Host answered: '%s'", input_msg);

//	kfree(output_msg);
//	kfree(input_msg);
	kfree(syscall_type);

	debug("Leaving");

	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;
	
	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	debug("registered %d devs, ret=%d", crypto_minor_cnt, ret);
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	debug("added with ret=%d", ret);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
