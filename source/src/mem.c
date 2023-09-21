
#include "mem.h"
#include "stdlib.h"
#include "string.h"
#include <pthread.h>
#include <stdio.h>

static BYTE _ram[RAM_SIZE];

static struct { // status of physical pages
	uint32_t proc;	// ID of process currently uses this page
	int index;	// Index of the page in the list of pages allocated
			// to the process.
	int next;	// The next page in the list. -1 if it is the last
			// page.
} _mem_stat [NUM_PAGES];

static pthread_mutex_t mem_lock;

void init_mem(void) {
	memset(_mem_stat, 0, sizeof(*_mem_stat) * NUM_PAGES);
	memset(_ram, 0, sizeof(BYTE) * RAM_SIZE);
	pthread_mutex_init(&mem_lock, NULL);
}

/* get offset of the virtual address */
static addr_t get_offset(addr_t addr) {
	return addr & ~((~0U) << OFFSET_LEN); //return 10 bits LSB of virtual address <-> offset
}

/* get the first layer index */
static addr_t get_first_lv(addr_t addr) {
	return addr >> (OFFSET_LEN + PAGE_LEN); // return 5 bits MSB <-> the first layer index
}

/* get the second layer index */
static addr_t get_second_lv(addr_t addr) {
	return (addr >> OFFSET_LEN) - (get_first_lv(addr) << PAGE_LEN);
}

/* Search for page table table from the a segment table */
static struct trans_table_t * get_trans_table(
		addr_t index, 	// Segment level index
		struct page_table_t * page_table) { // first level table
	
	/*
	 * TODO: Given the Segment index [index], you must go through each
	 * row of the segment table [page_table] and check if the v_index
	 * field of the row is equal to the index
	 *
	 * */

	int i;
	for (i = 0; i < page_table->size; i++) {
		// Enter your code here
		if(page_table->table[i].v_index == index)
			return page_table->table[i].next_lv;
	}
	return NULL;
}

/* Translate virtual address to physical address. If [virtual_addr] is valid,
 * return 1 and write its physical counterpart to [physical_addr].
 * Otherwise, return 0 */
static int translate(
		addr_t virtual_addr, 	// Given virtual address
		addr_t * physical_addr, // Physical address to be returned
		struct pcb_t * proc) {  // Process uses given virtual address

	/* Offset of the virtual address */
	addr_t offset = get_offset(virtual_addr);
	/* The first layer index */
	addr_t first_lv = get_first_lv(virtual_addr);
	/* The second layer index */
	addr_t second_lv = get_second_lv(virtual_addr);
	
	/* Search in the first level */
	struct trans_table_t * trans_table = NULL;// page table of segment
	trans_table = get_trans_table(first_lv, (struct page_table_t*)proc->page_table);
	if (trans_table == NULL) {
		return 0;
	}

	int i;
	for (i = 0; i < trans_table->size; i++) {
		if (trans_table->table[i].v_index == second_lv) {
			/* TODO: Concatenate the offset of the virtual addess
			 * to [p_index] field of trans_table->table[i] to 
			 * produce the correct physical address and save it to
			 * [*physical_addr]  */
			
			addr_t frame_address = trans_table->table[i].p_index << OFFSET_LEN;//physical address of frame
			*physical_addr = frame_address + offset;
			return 1;
		}
	}
	return 0;	
}

addr_t alloc_mem(uint32_t size, struct pcb_t * proc) {
	pthread_mutex_lock(&mem_lock);
	addr_t ret_mem = 0;
	/* TODO: Allocate [size] byte in the memory for the
	 * process [proc] and save the address of the first
	 * byte in the allocated memory region to [ret_mem].
	 * */

	uint32_t num_pages = (size % PAGE_SIZE) ? size / PAGE_SIZE + 1:
		size / PAGE_SIZE; // Number of pages we will use
	int mem_avail = 0; // We could allocate new memory region or not?

	/* First we must check if the amount of free memory in
	 * virtual address space and physical address space is
	 * large enough to represent the amount of required 
	 * memory. If so, set 1 to [mem_avail].
	 * Hint: check [proc] bit in each page of _mem_stat
	 * to know whether this page has been used by a process.
	 * For virtual memory space, check bp (break pointer).
	 * */

	//check virtual memory
	if(proc->bp + num_pages * PAGE_SIZE > (1 << ADDRESS_SIZE)){
		pthread_mutex_unlock(&mem_lock);
		return ret_mem;
	}
	// check free frame in physical memory
	addr_t free_frame[num_pages];//index of free frame in _mem_stat
	uint32_t num_pages_free = 0;	
	for(int i = 0; i < NUM_PAGES; i++){
		if(_mem_stat[i].proc == 0){// fram index i in ram is free
			free_frame[num_pages_free] = i;// update free frame for arr
			num_pages_free++;
			if(num_pages_free == num_pages){//enough free frame for allocate
				mem_avail = 1;
				break;
			}
		}
	}
	
	
	if (mem_avail) {
		/* We could allocate new memory region to the process */
		ret_mem = proc->bp;
		proc->bp += num_pages * PAGE_SIZE;
		/* Update status of physical pages which will be allocated
		 * to [proc] in _mem_stat. Tasks to do:
		 * 	- Update [proc], [index], and [next] field
		 * 	- Add entries to segment table page tables of [proc]
		 * 	  to ensure accesses to allocated memory slot is
		 * 	  valid. */

		struct page_table_t* page_table = (struct page_table_t*)proc->page_table;
		addr_t address = ret_mem; 
		for(uint32_t i = 0; i < num_pages; i++){
			addr_t p_idx = free_frame[i];

			//update physical addr
			_mem_stat[p_idx].proc = proc->pid;
			_mem_stat[p_idx].index = i;
			if(i == num_pages - 1)
				_mem_stat[p_idx].next = -1;
			else
				_mem_stat[p_idx].next = free_frame[i+1];

			//update virtual addr
			addr_t seg_idx = get_first_lv(address);
			addr_t page_idx = get_second_lv(address);
			//page_table in seg_idx entry in seg_table
			struct trans_table_t* trans_table = get_trans_table(seg_idx, page_table);
			//segment_table not exist entry with seg_idx
			if(trans_table == NULL){
				//create new page table for seg_idx entry in segment_table
				page_table->table[page_table->size].v_index = seg_idx;
				page_table->table[page_table->size].next_lv = malloc(sizeof(struct trans_table_t));
				trans_table = page_table->table[page_table->size].next_lv;
				trans_table->size = 0;
				page_table->size++;
			}
			trans_table->table[trans_table->size].v_index = page_idx;
			trans_table->table[trans_table->size].p_index = p_idx;
			trans_table->size++;
			address += PAGE_SIZE;
		}
	}
	pthread_mutex_unlock(&mem_lock);
	return ret_mem;
}
//move last entry of page_table to entry has v_index = v_idx 
void swap_page_entry(struct trans_table_t* trans_table, addr_t page_idx);
//move last entry of seg_table to entry has v_index = seg_idx 
void swap_seg_entry(struct page_table_t* page_table, addr_t seg_idx);

int free_mem(addr_t address, struct pcb_t * proc) {
	/*TODO: Release memory region allocated by [proc]. The first byte of
	 * this region is indicated by [address]. Task to do:
	 * 	- Set flag [proc] of physical page use by the memory block
	 * 	  back to zero to indicate that it is free.
	 * 	- Remove unused entries in segment table and page tables of
	 * 	  the process [proc].
	 * 	- Remember to use lock to protect the memory from other
	 * 	  processes.  */
	pthread_mutex_lock(&mem_lock);
	addr_t p_addr;//physical address
	if(translate(address, &p_addr, proc) == 0){
		perror("Segment fault");
		exit(EXIT_FAILURE);
	}
	struct page_table_t* page_table = (struct page_table_t*)proc->page_table;//seg_table
	addr_t p_idx = p_addr >> OFFSET_LEN;//frame index
	int next = _mem_stat[p_idx].next;//next index of frame in physical memory 
	do{
		next = _mem_stat[p_idx].next;
		//update physical memory
		_mem_stat[p_idx].proc = 0;
		p_idx = _mem_stat[p_idx].next;

		//update virtual memory
		addr_t seg_idx = get_first_lv(address);
		addr_t page_idx = get_second_lv(address);
		//move last entry of page_table to entry with page_idx
		struct trans_table_t* trans_table = get_trans_table(seg_idx, page_table);
		swap_page_entry(trans_table, page_idx);
		trans_table->size --;
		
		if(trans_table->size == 0){// free this page_table
			//move last entry of seg_table to entry with seg_idx
			swap_seg_entry(page_table, seg_idx);
			free(trans_table);
			page_table->size --;
		}
		address += PAGE_SIZE;
	}while(next != -1);
	//update break pointer
	if(address == proc->bp){
		while(proc->bp != PAGE_SIZE){
			if(translate(proc->bp, &p_addr, proc) == 0)
				proc->bp -= PAGE_SIZE;
			else break;	
		}
	}
	pthread_mutex_unlock(&mem_lock);
	return 0;
}

int read_mem(addr_t address, struct pcb_t * proc, BYTE * data) {
	addr_t physical_addr;
	if (translate(address, &physical_addr, proc)) {
		*data = _ram[physical_addr];
		return 0;
	}else{
		return 1;
	}
}

int write_mem(addr_t address, struct pcb_t * proc, BYTE data) {
	addr_t physical_addr;
	if (translate(address, &physical_addr, proc)) {
		_ram[physical_addr] = data;
		return 0;
	}else{
		return 1;
	}
}

void dump(void) {
	int i;
	for (i = 0; i < NUM_PAGES; i++) {
		if (_mem_stat[i].proc != 0) {
			printf("%03d: ", i);
			printf("%05x-%05x - PID: %02d (idx %03d, nxt: %03d)\n",
				i << OFFSET_LEN,
				((i + 1) << OFFSET_LEN) - 1,
				_mem_stat[i].proc,
				_mem_stat[i].index,
				_mem_stat[i].next
			);
			int j;
			for (	j = i << OFFSET_LEN;
				j < ((i+1) << OFFSET_LEN) - 1;
				j++) {
				
				if (_ram[j] != 0) {
					printf("\t%05x: %02x\n", j, _ram[j]);
				}
					
			}
		}
	}
}

//move last entry of page_table to entry has v_index = v_idx 
void swap_page_entry(struct trans_table_t* trans_table, addr_t page_idx){
	uint32_t page_idx_last = trans_table->size - 1;
	for(uint32_t i = 0; i <= page_idx_last; i++){
		if(trans_table->table[i].v_index == page_idx){
			if(i == page_idx_last) break;
			trans_table->table[i].v_index = trans_table->table[page_idx_last].v_index;
			trans_table->table[i].p_index = trans_table->table[page_idx_last].p_index;
			break;
		}
	}
}
//move last entry of seg_table to entry has v_index = seg_idx 
void swap_seg_entry(struct page_table_t* page_table, addr_t seg_idx){
	uint32_t seg_idx_last = page_table->size - 1;
	for(uint32_t i = 0; i <= seg_idx_last; i++){
		if(page_table->table[i].v_index == seg_idx){
			if(i == seg_idx_last) break;
			page_table->table[i].v_index = page_table->table[seg_idx_last].v_index;
			page_table->table[i].next_lv = page_table->table[seg_idx_last].next_lv;
			page_table->table[seg_idx_last].next_lv = NULL;
			break;
		}
	}
}
