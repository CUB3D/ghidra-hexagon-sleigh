package pw.cub3d.hexagon;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Label;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.zip.InflaterInputStream;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import generic.theme.GIcon;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;

public class QdbViewerProvider extends ComponentProviderAdapter {
		private JPanel mainPanel;
		private DockingAction action;
		
		private DefaultTableModel model;
		private JButton searchFor;
		private JButton decodeBtn;
		private JTextField resultTxt;
		private QDBFile.Entry selection;
		
		private QDBFile loadedQdb;
		

		public QdbViewerProvider(PluginTool tool, String owner) {
			super(tool, "QDB", owner);
			buildMainPanel();
			setIcon(new GIcon("icon.sample.provider"));
			setDefaultWindowPosition(WindowPosition.WINDOW);
			setTitle("QDB Viewer");
			setVisible(true);
			createActions();
		}
		
		class QDBFile {
			class Entry {
				private int hash;
				private String msg;
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
	            	ent.hash = Integer.decode(parts[0]);
	            	ent.msg = String.join(":", Arrays.copyOfRange(parts, 5, parts.length));
            		this.hashesToLogs.add(ent);
	            }
			}
		}

		private void createActions() {
			action = new DockingAction("Load QDB", getOwner()) {
				@Override
				public void actionPerformed(ActionContext context) {
					JFileChooser fileChooser = new JFileChooser();
	                
	                FileNameExtensionFilter filter = new FileNameExtensionFilter("Text Files (*.qdb)", "qdb");
	                fileChooser.setFileFilter(filter);

	                int result = fileChooser.showOpenDialog(mainPanel);

	                if (result == JFileChooser.APPROVE_OPTION) {
	                    File selectedFile = fileChooser.getSelectedFile();
	                    
	                    try {
	            			byte[] data = Files.readAllBytes(selectedFile.toPath());
	                    	loadedQdb = new QDBFile(data);
	                    	searchFor.setEnabled(false);
	                    	decodeBtn.setEnabled(false);
	                    	selection = null;
	                    	
	                    	Object[][] tblData = new Object[loadedQdb.hashesToLogs.size()][3];
	                    	for(int i = 0; i < loadedQdb.hashesToLogs.size(); i++) {
	                    		tblData[i][0] = i;
	                    		tblData[i][1] = loadedQdb.hashesToLogs.get(i).hash;
	                    		tblData[i][2] = loadedQdb.hashesToLogs.get(i).msg;
	                    	}
	                    	String[] columnNames = {"#", "Hash", "Message"};
	                    	model.setDataVector(tblData, columnNames);
	                    }catch(Exception e) {
	                    	e.printStackTrace();
	                    }
	                    
	                    
	                }
				}
			};

			action.setEnabled(true);
			javax.swing.Icon icon = new GIcon("icon.sample.action.hello.world");
			action.setToolBarData(new ToolBarData(icon));
			action.setDescription("Load QDB file");
			addLocalAction(action);
		}

		@Override
		public JComponent getComponent() {
			return mainPanel;
		}

		private void buildMainPanel() {
			mainPanel = new JPanel(new GridBagLayout());
			mainPanel.setBorder(BorderFactory.createEmptyBorder());
			GridBagConstraints c = new GridBagConstraints();
			
			String[] columnNames = {"#", "Hash", "Message"};
			model = new DefaultTableModel(columnNames, 0) {
				@Override
				public boolean isCellEditable(int row, int column) {
					return false;
				}
			};
			JTable table = new JTable(model);
			table.setRowSelectionAllowed(true);
			table.setColumnSelectionAllowed(false);
			table.setCellSelectionEnabled(false);
			
			TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(model);
			table.setRowSorter(sorter);
			
			table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
			
			table.getSelectionModel().addListSelectionListener(e -> {
				int row = table.getSelectedRow();
				int idx = Integer.decode(table.getValueAt(row, 0).toString());
				selection = loadedQdb.hashesToLogs.get(idx);
				searchFor.setEnabled(true);
				decodeBtn.setEnabled(true);
			});
            JScrollPane scrollPane = new JScrollPane(table);
            c.gridx = 0;
            c.gridy = 0;
            c.fill = GridBagConstraints.HORIZONTAL;
            c.gridwidth = 3;
            mainPanel.add(scrollPane, c);
            
            searchFor = new JButton("Search Selected");
            searchFor.addActionListener(e -> {
            	long targetValue = (0x1f000000 + selection.hash) << 3;
            	Memory mem = getProgram().getMemory();
            	
            	byte[] nedl = new byte[4];
            	nedl[0] = (byte) (targetValue & 0xFF);
            	nedl[1] = (byte) ((targetValue >> 8) & 0xFF);
            	nedl[2] = (byte) ((targetValue >> 16) & 0xFF);
            	nedl[3] = (byte) ((targetValue >> 24) & 0xFF);
            	
            	Address results = mem.findBytes(mem.getMinAddress(), nedl, null, true, TaskMonitor.DUMMY);
            	            	
            	if(results != null) {           	
            		resultTxt.setText(results.toString());
            	} else {
            		resultTxt.setText("Log not found");
            	}
            });
            searchFor.setEnabled(false);
            c.gridx = 0;
            c.gridy = 3;
            c.fill = GridBagConstraints.HORIZONTAL;
            c.gridwidth = 3;
            mainPanel.add(searchFor, c);
            
            JTextField search = new JTextField();
            search.getDocument().addDocumentListener(new DocumentListener() {
				@Override
				public void removeUpdate(DocumentEvent e) { updateFilter(); }
				@Override
				public void insertUpdate(DocumentEvent e) { updateFilter(); }
				@Override
				public void changedUpdate(DocumentEvent e) { updateFilter(); }
				
				private void updateFilter() {
                    String text = search.getText();
                    if (text.trim().isEmpty()) {
                        sorter.setRowFilter(null);
                    } else {
                        sorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(text), 2));
                    }
                }
			});
            
            c.gridx = 0;
            c.gridy = 4;
            c.gridwidth = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            mainPanel.add(new Label("Fitler:"), c);
            
            c.gridx = 1;
            c.gridy = 4;
            c.gridwidth = 2;
            c.fill = GridBagConstraints.HORIZONTAL;
            mainPanel.add(search, c);
            
            c.gridx = 0;
            c.gridy = 5;
            c.gridwidth = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            mainPanel.add(new Label("Decode:"), c);
            
            JTextField decode = new JTextField();
            c.gridx = 1;
            c.gridy = 5;
            c.gridwidth = 2;
            c.fill = GridBagConstraints.HORIZONTAL;
            mainPanel.add(decode, c);
            
            decodeBtn = new JButton("Decode");
            decodeBtn.setEnabled(false);
            decodeBtn.addActionListener(e -> {
            	long msg_id = Long.decode(decode.getText());
            	
            	long kind = (msg_id >> 24) & 0xFF;
            	long msg_idx = msg_id & 0xFFFFF;
    			if (kind == 0xf3) {
    				msg_idx = (msg_idx >>4);
    			}else if (kind == 0xf2) {
    				msg_idx = (msg_idx >>4) | (1<<14);
    			} else if (kind == 0xf8) {
    				msg_idx = (msg_id & 0xFFFFFF) >> 3;
    			}
    			
    			QDBFile.Entry ent = null;
    			for(QDBFile.Entry ee : loadedQdb.hashesToLogs) {
    				if(ee.hash == msg_idx) {
    					ent = ee;
    					break;
    				}
    			}
            	
            	if(ent != null) {           	
            		resultTxt.setText(ent.msg);
            	} else {
            		resultTxt.setText("Hash not found in QDB");
            	}
            });
            c.gridx = 0;
            c.gridy = 6;
            c.gridwidth = 3;
            c.fill = GridBagConstraints.HORIZONTAL;
            mainPanel.add(decodeBtn, c);
            
            
            c.gridx = 0;
            c.gridy = 7;
            c.gridwidth = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            mainPanel.add(new Label("Result:"), c);
            
            c.gridx = 1;
            c.gridy = 7;
            c.gridwidth = 2;
            c.fill = GridBagConstraints.HORIZONTAL;
            resultTxt = new JTextField();
            resultTxt.setEditable(false);
            mainPanel.add(resultTxt, c);
		}

		private Program getProgram() {

			ProgramManager pm = tool.getService(ProgramManager.class);
			if (pm != null) {
				return pm.getCurrentProgram();
			}
			return null;
	    }
		
}
