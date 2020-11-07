/*
 * Virtio Cryptodev Device
 *
 * Implementation of virtio-cryptodev qemu backend device.
 *
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr> 
 * Konstantinos Papazafeiropoulos <kpapazaf@cslab.ece.ntua.gr>
 *
 */

#include "qemu/osdep.h"
#include "qemu/iov.h"
#include "hw/qdev.h"
#include "hw/virtio/virtio.h"
#include "standard-headers/linux/virtio_ids.h"
#include "hw/virtio/virtio-cryptodev.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>

static uint64_t get_features(VirtIODevice *vdev, uint64_t features,
                             Error **errp)
{
    DEBUG_IN();
    return features;
}

static void get_config(VirtIODevice *vdev, uint8_t *config_data)
{
    DEBUG_IN();
}

static void set_config(VirtIODevice *vdev, const uint8_t *config_data)
{
    DEBUG_IN();
}

static void set_status(VirtIODevice *vdev, uint8_t status)
{
	DEBUG_IN();
    printf("[set_status] called for name=%s, status=%d, device_id=%d\n", vdev->name, vdev->status, vdev->device_id);
}

static void vser_reset(VirtIODevice *vdev)
{
    DEBUG_IN();
}

static void vq_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtQueueElement *elem;
    unsigned int *syscall_type;
    int *host_fd;
    unsigned int *ioctl_cmd;
    int *host_return_val; //must do at frontend too
    unsigned char *dst, *src, *iv, *old_dst, *old_iv, *old_src;
    struct crypt_op *crypt_op;
    struct session_op *session_op;
    unsigned char *session_key;
    unsigned int *ses_id;

    DEBUG_IN();

    elem = virtqueue_pop(vq, sizeof(VirtQueueElement));
    if (!elem) {
        DEBUG("No item to pop from VQ :(");
        return;
    } 

    DEBUG("I have got an item from VQ :)");
	//DEBUG("wtf");

//	int *host_fd;

	syscall_type = elem->out_sg[0].iov_base;
    switch (*syscall_type) {
    case VIRTIO_CRYPTODEV_SYSCALL_TYPE_OPEN:
        DEBUG("VIRTIO_CRYPTODEV_SYSCALL_TYPE_OPEN");
        /* ?? */
	DEBUG("preparing to open");
	//int fd = open("/dev/crypto", O_RDWR, 0);
	int fd = open("/dev/crypto", O_RDWR);
	if (fd < 0) {
		perror("open:/dev/crypto");
	}

	printf("Printf: Opened /dev/crypto with fd=%d\n", fd);
	host_fd = elem->in_sg[0].iov_base;
	//memcpy(host_fd, &fd, sizeof(int));
       	*host_fd = fd;

	break;

    case VIRTIO_CRYPTODEV_SYSCALL_TYPE_CLOSE:
        DEBUG("VIRTIO_CRYPTODEV_SYSCALL_TYPE_CLOSE");
        /* ?? */
	host_fd = elem->out_sg[1].iov_base;
	printf("Printf: closed /dev/crypto with fd=%d\n", *host_fd);
	if (close(*host_fd) < 0) {
		perror("close:host_fd");
	}

        break;

    case VIRTIO_CRYPTODEV_SYSCALL_TYPE_IOCTL:
        DEBUG("VIRTIO_CRYPTODEV_SYSCALL_TYPE_IOCTL");
        /* ?? */
//      int *host_fd;
//	unsigned int *ioctl_cmd;
//	int *host_return_val; //must do at frontend too
//	unsigned char *dst;//, *src, *iv;
//	struct crypt_op *crypt_op;
//	struct session_op *session_op;
//	unsigned char *session_key;
//	unsigned int *ses_id;

        host_fd = elem->out_sg[1].iov_base;
	ioctl_cmd = elem->out_sg[2].iov_base;

	switch (*ioctl_cmd) {
	case CIOCGSESSION:

		DEBUG("CIOCGSESSION");

		session_key = elem->out_sg[3].iov_base;
		session_op = elem->in_sg[0].iov_base;
		session_op->key = session_key;
		host_return_val = elem->in_sg[1].iov_base;

		printf("host_fd: %d\n", *host_fd);

		*host_return_val = ioctl(*host_fd, *ioctl_cmd, session_op); 
		if (*host_return_val < 0) {
			perror("ioctl");
		}

		printf("ses: %u\n", session_op->ses);
		printf("sess.keylen: %d\n", session_op->keylen);

		break;
	case CIOCFSESSION:
		DEBUG("CIOCFSESSION");

		ses_id = elem->out_sg[3].iov_base;
		host_return_val = elem->in_sg[0].iov_base;

		*host_return_val = ioctl(*host_fd, *ioctl_cmd, ses_id); // or *ses_id ???
		if (*host_return_val < 0) {
			perror("ioctl");
		}
		break;

	case CIOCCRYPT:
		DEBUG("CIOCCRYPT");

		crypt_op = elem->out_sg[3].iov_base;
		printf("ses_id:  %d\n", crypt_op->ses);
		printf("host_fd: %d\n", *host_fd);
		printf("crypt_op->op: %d\n", crypt_op->op);

		//unsigned char *src, *dst, *iv;
		src = elem->out_sg[4].iov_base;
		iv = elem->out_sg[5].iov_base;
		dst = elem->in_sg[0].iov_base;

		old_src = crypt_op->src;
		old_iv = crypt_op->iv;
		old_dst = crypt_op->dst;

		crypt_op->src = src;
		crypt_op->iv = iv;
		crypt_op->dst = dst;

		
		host_return_val = elem->in_sg[1].iov_base;
		*host_return_val = ioctl(*host_fd, *ioctl_cmd, crypt_op); // or *ses_id ???
		if (*host_return_val < 0) {
			perror("ioctl");
		}

		crypt_op->src = old_src;
		crypt_op->iv = old_iv;
		crypt_op->dst = old_dst;
		
		break;
	}
        
	break;

    default:
        DEBUG("Unknown syscall_type");
        break;
    }
	printf("Pushing fd to vq, and notify\n");

    virtqueue_push(vq, elem, 0);
    virtio_notify(vdev, vq);
    g_free(elem);
}

static void virtio_cryptodev_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

    DEBUG_IN();

    virtio_init(vdev, "virtio-cryptodev", VIRTIO_ID_CRYPTODEV, 0);
    virtio_add_queue(vdev, 128, vq_handle_output);
}

static void virtio_cryptodev_unrealize(DeviceState *dev, Error **errp)
{
    DEBUG_IN();
}

static Property virtio_cryptodev_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_cryptodev_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *k = VIRTIO_DEVICE_CLASS(klass);

    DEBUG_IN();
    dc->props = virtio_cryptodev_properties;
    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);

    k->realize = virtio_cryptodev_realize;
    k->unrealize = virtio_cryptodev_unrealize;
    k->get_features = get_features;
    k->get_config = get_config;
    k->set_config = set_config;
    k->set_status = set_status;
    k->reset = vser_reset;
}

static const TypeInfo virtio_cryptodev_info = {
    .name          = TYPE_VIRTIO_CRYPTODEV,
    .parent        = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtCryptodev),
    .class_init    = virtio_cryptodev_class_init,
};

static void virtio_cryptodev_register_types(void)
{
    type_register_static(&virtio_cryptodev_info);
}

type_init(virtio_cryptodev_register_types)
