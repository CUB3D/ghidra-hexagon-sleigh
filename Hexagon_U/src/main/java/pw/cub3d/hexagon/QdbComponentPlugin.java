package pw.cub3d.hexagon;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

@PluginInfo(
		status = PluginStatus.RELEASED,
		packageName = "Qualcomm",
		category = PluginCategoryNames.CODE_VIEWER,
		shortDescription = "QDB viewer",
		description = "Plugin to interact with QDB files"
	)
public class QdbComponentPlugin extends Plugin {
	private QdbViewerProvider provider;

	/** 
	  * Constructor - Setup the plugin
	  */
	public QdbComponentPlugin(PluginTool tool) {
		super(tool);

		provider = new QdbViewerProvider(tool, getName());
	}

	@Override
	public void dispose() {
		provider.setVisible(false);

		// The plugin is getting removed from the tool; do any clean up
		// here and release resources if necessary.
	}
}
