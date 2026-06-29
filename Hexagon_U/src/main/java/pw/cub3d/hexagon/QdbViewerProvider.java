package pw.cub3d.hexagon;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Label;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.nio.file.Files;
import java.util.regex.Pattern;
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
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
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
			setIcon(new GIcon("icon.plugin.datatypes.util.closed.folder.locked"));
			setDefaultWindowPosition(WindowPosition.WINDOW);
			setTitle("QDB Viewer");
			setVisible(true);
			
			action = new DockingAction("Load QDB", getOwner()) {
				@Override
				public void actionPerformed(ActionContext context) {
					onLoadFile();
				}
			};

			action.setEnabled(true);
			javax.swing.Icon icon = new GIcon("icon.drive");
			action.setToolBarData(new ToolBarData(icon));
			action.setDescription("Load QDB file");
			addLocalAction(action);
		}
		
		public void onLoadFile() {
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
                	decodeBtn.setEnabled(true);
                	selection = null;
                	
                	Object[][] tblData = new Object[loadedQdb.getEntries().size()][3];
                	for(int i = 0; i < loadedQdb.getEntries().size(); i++) {
                		tblData[i][0] = i;
                		tblData[i][1] = loadedQdb.getEntries().get(i).getHash();
                		tblData[i][2] = loadedQdb.getEntries().get(i).getMessage();
                	}
                	String[] columnNames = {"#", "Hash", "Message"};
                	model.setDataVector(tblData, columnNames);
                }catch(Exception e) {
                	e.printStackTrace();
                }
            }
		}
		
		private Address findInCode(Memory mem, long tgt) {
			Listing l = getProgram().getListing();
        	
        	
        	AddressRangeIterator itr = mem.getAddressRanges();
        	for(AddressRange range : itr) {
        		AddressSet as = new AddressSet(range.getMinAddress(), range.getMaxAddress());
        		InstructionIterator it = l.getInstructions(as, true);
        		
        		
        		for(Instruction i : it) {
        			int num_ops = i.getNumOperands();
        			for(int op = 0; op < num_ops; op++) {
        				Object[] ops = i.getOpObjects(op);
        				ghidra.program.model.symbol.Reference[] opRefs = i.getOperandReferences(op);
        				
        				if(opRefs.length == 0) {
        					for(Object opO : ops) {
        						if(opO instanceof Scalar) {
        							Scalar s = (Scalar) opO;
        							if(s.getUnsignedValue() == tgt) {
        								return i.getAddress();
        							}
        						}
        					}
        				}
        				
        			}
        		}
        		
        	}
        	return null;
		}
		
		private void setResult(String result, boolean success) {
    		resultTxt.setText(result);
    		
    		if(success) {
    			StringSelection ss1 = new StringSelection(result);
            	Toolkit.getDefaultToolkit().getSystemClipboard().setContents(ss1, ss1);
    		}
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
				selection = null;
				searchFor.setEnabled(false);
				
				try {
					int row = table.getSelectedRow();
					int idx = Integer.decode(table.getValueAt(row, 0).toString());
					selection = loadedQdb.getEntries().get(idx);
					searchFor.setEnabled(true);
				} catch (Exception ee) {
					ee.printStackTrace();
				}
			});
            JScrollPane scrollPane = new JScrollPane(table);
            c.gridx = 0;
            c.gridy = 0;
            c.weightx = 1;
            c.weighty = 2;
            c.fill = GridBagConstraints.BOTH;
            c.gridwidth = GridBagConstraints.REMAINDER;
            mainPanel.add(scrollPane, c);
            
            searchFor = new JButton("Search Selected");
            searchFor.addActionListener(e -> {
            	long targetValue = (0x1f000000 + selection.getHash()) << 3;
            	Memory mem = getProgram().getMemory();
            	
            	byte[] nedl = new byte[4];
            	nedl[0] = (byte) (targetValue & 0xFF);
            	nedl[1] = (byte) ((targetValue >> 8) & 0xFF);
            	nedl[2] = (byte) ((targetValue >> 16) & 0xFF);
            	nedl[3] = (byte) ((targetValue >> 24) & 0xFF);
            	
        		setResult("Searching", false);
            	
            	Address results = mem.findBytes(mem.getMinAddress(), nedl, null, true, TaskMonitor.DUMMY);
            	            	
            	if(results != null) {           	
            		setResult(results.toString(), true);
            	} else {
            		setResult("Log not found for " + String.format("%x", targetValue), false);
            		
            		results = findInCode(mem, targetValue);
            		
            		if(results != null) {           	
                		setResult(results.toString(), true);
                	} else {
                		setResult("Log not found for " + String.format("%x", targetValue), false);
                	}
            	}
            	
            	
            });
            searchFor.setEnabled(false);
            c.gridx = 0;
            c.gridy = 3;
            c.weightx = 1;
            c.weighty = 0;
            c.fill = GridBagConstraints.HORIZONTAL;
            c.gridwidth = GridBagConstraints.REMAINDER;
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
            c.weightx = 0;
            c.weighty = 0;
            c.fill = GridBagConstraints.HORIZONTAL;
            mainPanel.add(new Label("Filter:"), c);
            
            c.gridx = 1;
            c.gridy = 4;
            c.weightx = 1;
            c.weighty = 0;
            c.gridwidth = GridBagConstraints.REMAINDER;
            c.fill = GridBagConstraints.HORIZONTAL;
            mainPanel.add(search, c);
            
            c.gridx = 0;
            c.gridy = 5;
            c.gridwidth = 1;
            c.weightx = 0;
            c.weighty = 0;
            c.fill = GridBagConstraints.HORIZONTAL;
            mainPanel.add(new Label("Decode:"), c);
            
            JTextField decode = new JTextField();
            c.gridx = 1;
            c.gridy = 5;
            c.weightx = 1;
            c.weighty = 0;
            c.gridwidth = GridBagConstraints.REMAINDER;
            c.fill = GridBagConstraints.HORIZONTAL;
            mainPanel.add(decode, c);
            
            decodeBtn = new JButton("Decode");
            decodeBtn.setEnabled(false);
            decodeBtn.addActionListener(e -> {
            	try {
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
	    			
	    			QDBFile.Entry ent = loadedQdb.getByHash(msg_idx);
	    			
	            	if(ent != null) {
	            		setResult(ent.getMessage(), true);
	            	} else {
	            		setResult("Hash not found in QDB", false);
	            	}
            	} catch (Exception ee) {
            		ee.printStackTrace();
            		resultTxt.setText("Failed!");
            	}
            });
            c.gridx = 0;
            c.gridy = 6;
            c.weightx = 1;
            c.weighty = 0;
            c.gridwidth = GridBagConstraints.REMAINDER;
            c.fill = GridBagConstraints.HORIZONTAL;
            mainPanel.add(decodeBtn, c);
            
            
            c.gridx = 0;
            c.gridy = 7;
            c.gridwidth = 1;
            c.weightx = 0;
            c.weighty = 0;
            c.fill = GridBagConstraints.HORIZONTAL;
            mainPanel.add(new Label("Result:"), c);
            
            c.gridx = 1;
            c.gridy = 7;
            c.weightx = 1;
            c.weighty = 0;
            c.gridwidth = GridBagConstraints.REMAINDER;
            c.fill = GridBagConstraints.HORIZONTAL;
            resultTxt = new JTextField();
            resultTxt.setEditable(false);
            mainPanel.add(resultTxt, c);
		}
		
		@Override
		public JComponent getComponent() {
			return mainPanel;
		}

		private Program getProgram() {

			ProgramManager pm = tool.getService(ProgramManager.class);
			if (pm != null) {
				return pm.getCurrentProgram();
			}
			return null;
	    }
		
}
