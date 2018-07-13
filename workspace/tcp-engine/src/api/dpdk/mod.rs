// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


use super::*;
use ::dpdk_unix::memory_information::PhysicalAddress;
use ::dpdk_unix::memory_information::VirtualAddress;


include!("DpdkNetworkPacket.rs");
include!("DpdkTransmissionControlBlockAbstractions.rs");



// todo: write a sampl program to see how remap_file_pages and virtual memory => physical memory interact. Can we get away with just finding one virtual address?



rte_iova_t
rte_mem_virt2iova(const void *virtaddr)
{
	if (rte_eal_iova_mode() == RTE_IOVA_VA)
		return (uintptr_t)virtaddr;
	return rte_mem_virt2phy(virtaddr);
}


let packet: *mut rte_mbuf;

let buffer_address: *mut c_void;
let mut buffer_length: u16;
let free_callback: rte_mbuf_extbuf_free_callback_t;
let free_callback_argument: *mut c_void = buf;

let shinfo: *mut rte_mbuf_ext_shared_info = unsafe { rust_rte_pktmbuf_ext_shinfo_init_helper(buffer_address, &mut buffer_length, free_callback, free_callback_argument) };

let buf_iova: rte_iova_t = unsafe { rust_rte_mempool_virt2iova(buf) + RTE_PTR_DIFF(buffer_address, buf) };
unsafe { rust_rte_pktmbuf_attach_extbuf(packet, buffer_address, buf_iova, buffer_length, shinfo) };
unsafe { rust_rte_pktmbuf_reset_headroom(packet) };

else {
			rte_iova_t buf_iova;
			struct rte_mbuf_ext_shared_info *shinfo;
			uint16_t buf_len = consumed_strd * strd_sz;

			/* Increment the refcnt of the whole chunk. */
			rte_atomic16_add_return(&buf->refcnt, 1);
			assert((uint16_t)rte_atomic16_read(&buf->refcnt) <=
			       strd_n + 1);
			addr = RTE_PTR_SUB(addr, RTE_PKTMBUF_HEADROOM);
			/*
			 * MLX5 device doesn't use iova but it is necessary in a
			 * case where the Rx packet is transmitted via a
			 * different PMD.
			 */
			buf_iova = rte_mempool_virt2iova(buf) +
				   RTE_PTR_DIFF(addr, buf);
			shinfo = rte_pktmbuf_ext_shinfo_init_helper(addr,
					&buf_len, mlx5_mprq_buf_free_cb, buf);
			/*
			 * EXT_ATTACHED_MBUF will be set to pkt->ol_flags when
			 * attaching the stride to mbuf and more offload flags
			 * will be added below by calling rxq_cq_to_mbuf().
			 * Other fields will be overwritten.
			 */
			rte_pktmbuf_attach_extbuf(pkt, addr, buf_iova, buf_len,
						  shinfo);
			rte_pktmbuf_reset_headroom(pkt);
			assert(pkt->ol_flags == EXT_ATTACHED_MBUF);
			/*
			 * Prevent potential overflow due to MTU change through
			 * kernel interface.
			 */
			if (unlikely(rte_pktmbuf_tailroom(pkt) < len)) {
				rte_pktmbuf_free_seg(pkt);
				++rxq->stats.idropped;
				continue;
			}
		}


*/
