package ghidra.program.emulation;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.pcode.exec.PcodeUseropLibraryFactory;
import ghidra.program.model.pcode.Varnode;
import ghidra.pcode.exec.PcodeUseropLibraryFactory.UseropLibrary;

@UseropLibrary(value = "QDSP6")
public class HexagonUPcodeUseropLibraryFactory implements PcodeUseropLibraryFactory {
	@Override
	public <T> PcodeUseropLibrary<T> create(SleighLanguage language, PcodeArithmetic<T> arithmetic) {
		return new HexagonUPcodeUseropLibrary<>();
	}

	public static class HexagonUPcodeUseropLibrary<T> extends AnnotatedPcodeUseropLibrary<T> {
		@PcodeUserop(functional = true)
		public long dcache_zero_addr(long addr) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long dcache_fetch(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long dcache_fetch_multi(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long instruction_sync(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long isync(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long cswi(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long ciad(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long l2fetch(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long memw_phys(Varnode[] inputs) throws Exception {
			throw new Exception("memw_phys is not implemented");
		}

		//TODO: wrong - see endloop0
		@PcodeUserop(variadic = true, functional = true)
		public long is_warmup_complete(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long atomic_aquire(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long atomic_release(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long memw_locked(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long memd_locked(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long memw_locked_store(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long memd_locked_store(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long dcache_clean_addr(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long dcache_cleaninv_addr(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long dcache_inv_addr(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long icache_inv_addr(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long barrier(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long memory_synch(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long dmsyncht(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long brkpt(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long diag(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long diag0(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long diag1(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long trace(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long trap0(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long trap1(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long trap2(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long pause(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long unpause(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long dckill(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long dcache_tag_read(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long dcache_clean_idx(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long dcache_cleaninv_idx(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long dcache_inv_idx(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long dcache_tag_write(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long icache_data_read(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long icache_tag_read(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long icache_inv_idx(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long ickill(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long icache_tag_write(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long icache_data_write(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long l2cache_clean_idx(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long l2cache_inv_idx(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long l2cache_clean_invalidate_idx(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long l2cache_inv_all(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long l2cache_global_clean(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long l2cache_global_clean_inv(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long l2cache_global_clean_range(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long l2cache_global_clean_inv_range(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long l2cache_global_unlock(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long l2locka(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long l2unlocka(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long l2tagw(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long l2tagr(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long crswap_0(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long getimask(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long iassignr(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long iassignw(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long nmi(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long resume(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long rte(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long setimask(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long setprio(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long siad(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long start(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long stop(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long swi(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long wait(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long tlblock(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long k0lock(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long tlbunlock(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long k0unlock(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long tlbw(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long tlbr(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long tlbp(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long tlbinvasid(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long ctlbw(Varnode[] inputs) {
			return 0;
		}

		@PcodeUserop(variadic = true, functional = true)
		public long tlboc(Varnode[] inputs) {
			return 0;
		}
	}
}
