package pw.cub3d.hexagon;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.InflaterInputStream;

class QDBFile {
	class Entry {
		private long hash;
		private String msg;
		
		public long getHash() {
			return this.hash;
		}
		public String getMessage() {
			return this.msg;
		}
	}
	
	private List<Entry> hashesToLogs;
	
	public QDBFile(byte[] data) throws IOException {
		// Skip 64 byte header
		byte[] compressedData = Arrays.copyOfRange(data, 64, data.length);
		
		// Decompress zlib stream
		 byte[] decompressedBytes;
        try (ByteArrayInputStream bais = new ByteArrayInputStream(compressedData);
             InflaterInputStream iis = new InflaterInputStream(bais);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[8192];
            int len;
            while ((len = iis.read(buffer)) != -1) {
                bos.write(buffer, 0, len);
            }
            decompressedBytes = bos.toByteArray();
        }

        
        this.hashesToLogs = new ArrayList<>();
        
        // Convert to string
        String decompressed = new String(decompressedBytes, StandardCharsets.UTF_8);

        for (String line : decompressed.split("\n", -1)) {
        	// Comment
        	if(line.startsWith("#")) {
        		continue;
        	}
        	String[] parts = line.split(":", -1);
        	// Not enough elements
        	if (parts.length < 5) {
        		continue;
        	}
        	// End of hashes
        	if (line.startsWith("<\\Contents>")) {
        		break;
        	}
        	
        	Entry ent = new Entry();
        	ent.hash = Long.decode(parts[0]);
        	ent.msg = String.join(":", Arrays.copyOfRange(parts, 5, parts.length));
    		this.hashesToLogs.add(ent);
        }
	}
	
	public List<Entry> getEntries() {
		return this.hashesToLogs;
	}
	
	public Entry getByHash(long hash) {
		for(Entry e : this.getEntries()) {
			if(e.getHash() == hash) {
				return e;
			}
		}
		return null;
	}
}
