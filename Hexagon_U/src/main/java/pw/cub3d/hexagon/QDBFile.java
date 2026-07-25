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
	enum FileSection {
		None,
		Content,
		MTraceContent,
		QTraceStrContent
		;
		
		public String getName() {
			switch (this) {
			case Content:
				return "Content";
			case MTraceContent:
				return "MTrace";
			case None:
				return "None???";
			case QTraceStrContent:
				return "QTraceStr";
			default:
				throw new IllegalArgumentException("Unreachable code");
			}
		}
	}
	
	class Entry {
		private long hash;
		private String msg;
		private FileSection section;
		
		public long getHash() {
			return this.hash;
		}
		public String getMessage() {
			return this.msg;
		}
		public FileSection getSection() {
			return this.section;
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

        FileSection section = FileSection.Content;
        
        for (String line : decompressed.split("\n", -1)) {
        	// Comment
        	if(line.startsWith("#")) {
        		continue;
        	}
        	
        	// Start of <Content>
        	if (line.startsWith("<Content>")) {
        		section = FileSection.Content;
        		continue;
        	}
        	// End of <Content>
        	if (line.startsWith("<\\Contents>")) {
        		section = FileSection.None;
        		continue;
        	}
        	// Start of <MtraceContent>
        	if (line.startsWith("<MtraceContent>")) {
        		section = FileSection.MTraceContent;
        		continue;
        	}
        	// End of <MtraceContent>
        	if (line.startsWith("<\\MtraceContent>")) {
        		section = FileSection.None;
        		continue;
        	}
        	// Start of <QtraceStrContent>
        	if (line.startsWith("<QtraceStrContent>")) {
        		section = FileSection.QTraceStrContent;
        		continue;
        	}
        	// End of <QtraceStrContent>
        	if (line.startsWith("<\\QtraceStrContent>")) {
        		section = FileSection.None;
        		continue;
        	}
        	
        	String[] parts = line.split(":", -1);
        	// Not enough elements
        	if (parts.length < 5 && section != FileSection.QTraceStrContent) {
        		continue;
        	}
        	// Need at least an ID
        	if(parts.length < 1) {
        		continue;
        	}
        	
        	// Don't add things if we aren't in a section
        	if(section == FileSection.None) {
        		continue;
        	}
        	
        	Entry ent = new Entry();
        	ent.section = section;
        	ent.hash = Long.decode(parts[0]);
        	if(section == FileSection.Content) {
        		ent.msg = String.join(":", Arrays.copyOfRange(parts, 5, parts.length));
        	} else if(section == FileSection.MTraceContent) {
    			// Seems to be some kind of redacted msg "4182270511:|7674088c:::::"
    			if(parts[2].isBlank() && parts[3].isBlank() && parts[4].isBlank()) {
    				ent.msg = String.join(":", Arrays.copyOfRange(parts, 1, parts.length));
    			} else {
    				// Normal format
    				ent.msg = String.join(":", Arrays.copyOfRange(parts, 5, parts.length));
    			}
        	} else if (section == FileSection.QTraceStrContent) {
        		// Seems to be for enum variants?
        		ent.msg = String.join(":", Arrays.copyOfRange(parts, 1, parts.length));
        	}
    		this.hashesToLogs.add(ent);
        }
	}
	
	public void merge(QDBFile other) {
		for(QDBFile.Entry otherEntry : other.hashesToLogs) {
			/// We run this as newfile.merge(oldfile) so we will prefer to keep existing (newfile) entries
			if(!this.hashesToLogs.stream().anyMatch(e -> (e.hash == otherEntry.hash) && (e.section == otherEntry.section))) {
				this.hashesToLogs.add(otherEntry);
			}
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
