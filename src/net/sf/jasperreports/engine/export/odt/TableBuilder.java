/*
 * ============================================================================
 * GNU Lesser General Public License
 * ============================================================================
 *
 * JasperReports - Free Java report-generating library.
 * Copyright (C) 2001-2006 JasperSoft Corporation http://www.jaspersoft.com
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 * 
 * JasperSoft Corporation
 * 303 Second Street, Suite 450 North
 * San Francisco, CA 94107
 * http://www.jaspersoft.com
 */

/*
 * Special thanks to Google 'Summer of Code 2005' program for supporting this development
 * 
 * Contributors:
 * Majid Ali Khan - majidkk@users.sourceforge.net
 * Frank Sch�nheit - Frank.Schoenheit@Sun.COM
 */
package net.sf.jasperreports.engine.export.odt;

import java.awt.Color;
import java.io.IOException;
import java.io.Writer;

import net.sf.jasperreports.engine.JRAlignment;
import net.sf.jasperreports.engine.JRBox;
import net.sf.jasperreports.engine.JRElement;
import net.sf.jasperreports.engine.JRGraphicElement;
import net.sf.jasperreports.engine.JRPrintElement;


public class TableBuilder 
{
	protected static final String VERTICAL_ALIGN_TOP = "top";
	protected static final String VERTICAL_ALIGN_MIDDLE = "middle";
	protected static final String VERTICAL_ALIGN_BOTTOM = "bottom";

	private String tableName = null;
	private int reportIndex = 0;
	private Writer bodyWriter = null;
	private Writer styleWriter = null;
	private int cellCounter = -1;
	private boolean isFrame = false;
	

	protected TableBuilder(
		String name, 
		Writer bodyWriter,
		Writer styleWriter
		) 
	{
		isFrame = true;
		
		this.bodyWriter = bodyWriter;
		this.styleWriter = styleWriter;

		this.tableName = "table_" + name;
	}

	protected TableBuilder(
		int reportIndex,
		int pageIndex,
		Writer bodyWriter,
		Writer styleWriter
		) 
	{
		isFrame = false;
		
		this.reportIndex = reportIndex;
		this.bodyWriter = bodyWriter;
		this.styleWriter = styleWriter;

		this.tableName = "table_" + reportIndex + "_" + pageIndex;
	}


	public void buildTableStyle() throws IOException 
	{
		styleWriter.write(" <style:style style:name=\"" + tableName + "\"");//FIXMEODT can we have only one page style per report?
		if (!isFrame)
		{
			styleWriter.write(" style:master-page-name=\"master_" + reportIndex +"\"");
		}
		styleWriter.write(" style:family=\"table\">\n");
		styleWriter.write("   <style:table-properties");		
//FIXMEODT
//		if (breakAfter != null) 
		if (!isFrame)
			styleWriter.write(" fo:break-after=\"page\"");
//		if (tableWidth != null)
//			styleWriter.write(" style:width=\""+ tableWidth +"in\"");
//		if (align != null)
//			styleWriter.write(" table:align=\""+ align +"\"");
//		if (margin != null)
//			styleWriter.write(" fo:margin=\""+ margin +"\"");
//		if (backGroundColor != null)
//			styleWriter.write(" fo:background-color=\""+ backGroundColor +"\"");
		styleWriter.write("/>\n");
		styleWriter.write(" </style:style>\n");
	}
	
	public void buildTableHeader() throws IOException 
	{
		bodyWriter.write("<table:table");
		if (isFrame)
		{
			bodyWriter.write(" is-subtable=\"true\"");
		}
		bodyWriter.write(" table:name=\"");
		bodyWriter.write(tableName);
		bodyWriter.write("\"");
		bodyWriter.write(" table:style-name=\"");
		bodyWriter.write(tableName);
		bodyWriter.write("\"");
		bodyWriter.write(">\n");
	}
	
	public void buildTableFooter() throws IOException 
	{
		bodyWriter.write("</table:table>\n");
	}
	
	public void buildRowStyle(int rowIndex, int rowHeight) throws IOException 
	{
		String rowName = tableName + "_row_" + rowIndex;
		styleWriter.write(" <style:style style:name=\"" + rowName + "\"");
		styleWriter.write(" style:family=\"table-row\">\n");
		styleWriter.write("   <style:table-row-properties");		
		styleWriter.write(" style:use-optimal-row-height=\"false\""); 
//FIXMEODT check this		styleWriter.write(" style:use-optimal-row-height=\"true\""); 
		styleWriter.write(" style:row-height=\"" + Utility.translatePixelsToInches(rowHeight) + "in\"");
		styleWriter.write("/>\n");
		styleWriter.write(" </style:style>\n");
	}

	public void buildRowHeader(int rowIndex) throws IOException 
	{
		String rowName = tableName + "_row_" + rowIndex;
		bodyWriter.write("<table:table-row");
		bodyWriter.write(" table:style-name=\"" + rowName + "\"");
		bodyWriter.write(">\n");
	}
	
	public void buildRowFooter() throws IOException 
	{
		bodyWriter.write("</table:table-row>\n");
	}
	
	public void buildColumnStyle(int colIndex, int colWidth) throws IOException 
	{
		String columnName = tableName + "_col_" + colIndex;
		styleWriter.write(" <style:style style:name=\"" + columnName + "\"");
		styleWriter.write(" style:family=\"table-column\">\n");
		styleWriter.write("   <style:table-column-properties");		
		styleWriter.write(" style:column-width=\"" + Utility.translatePixelsToInches(colWidth) + "in\"");
		styleWriter.write("/>\n");
		styleWriter.write(" </style:style>\n");
	}

	public void buildColumnHeader(int colIndex) throws IOException 
	{
		String columnName = tableName + "_col_" + colIndex;
		bodyWriter.write("<table:table-column");		
		bodyWriter.write(" table:style-name=\"" + columnName + "\"");
		bodyWriter.write(">\n");
	}

	public void buildColumnFooter() throws IOException 
	{
		bodyWriter.write("</table:table-column>\n");		
	}
	
	public void buildCellStyleHeader(JRPrintElement element) throws IOException 
	{
		String cellName = tableName + "_cell_" + (++cellCounter);
		styleWriter.append(" <style:style style:name=\"" + cellName + "\"");
		styleWriter.append(" style:family=\"table-cell\">\n");
		styleWriter.append("   <style:table-cell-properties");		
		styleWriter.append(" fo:wrap-option=\"wrap\"");
		styleWriter.append(" style:shrink-to-fit=\"false\"");
	}
	
	public void buildCellBackcolorStyle(JRPrintElement element) throws IOException 
	{
		if (element.getMode() == JRElement.MODE_OPAQUE)
		{
			String hexa = Integer.toHexString(element.getBackcolor().getRGB() & JROdtGridExporter.colorMask).toUpperCase();
			hexa = ("000000" + hexa).substring(hexa.length());
			styleWriter.append(" fo:background-color=\"#" + hexa + "\"");
		}
	}
	
	public void buildCellAlignmentStyle(JRAlignment alignment) throws IOException 
	{
		String verticalAlignment = VERTICAL_ALIGN_TOP;

		switch (alignment.getVerticalAlignment())
		{
			case JRAlignment.VERTICAL_ALIGN_BOTTOM :
			{
				verticalAlignment = VERTICAL_ALIGN_BOTTOM;
				break;
			}
			case JRAlignment.VERTICAL_ALIGN_MIDDLE :
			{
				verticalAlignment = VERTICAL_ALIGN_MIDDLE;
				break;
			}
			case JRAlignment.VERTICAL_ALIGN_TOP :
			default :
			{
				verticalAlignment = VERTICAL_ALIGN_TOP;
			}
		}

		if (!verticalAlignment.equals(VERTICAL_ALIGN_TOP))
		{
			styleWriter.write(" style:vertical-align=\"" + verticalAlignment + "\"");
		}
	}
	
	public void buildCellBorderStyle(JRPrintElement element, JRBox box) throws IOException 
	{
		if (box != null)
		{
			appendBorder(
				box.getTopBorder(),
				box.getTopBorderColor() == null ? element.getForecolor() : box.getTopBorderColor(),
				box.getTopPadding(),
				"top"
				);
			appendBorder(
				box.getLeftBorder(),
				box.getLeftBorderColor() == null ? element.getForecolor() : box.getLeftBorderColor(),
				box.getLeftPadding(),
				"left"
				);
			appendBorder(
				box.getBottomBorder(),
				box.getBottomBorderColor() == null ? element.getForecolor() : box.getBottomBorderColor(),
				box.getBottomPadding(),
				"bottom"
				);
			appendBorder(
				box.getRightBorder(),
				box.getRightBorderColor() == null ? element.getForecolor() : box.getRightBorderColor(),
				box.getRightPadding(),
				"right"
				);
		}
	}
	
	private void appendBorder(byte pen, Color borderColor, int padding, String side) throws IOException
	{
		String borderStyle = null;
		int borderWidth = 0;

		switch (pen)
		{
			case JRGraphicElement.PEN_DOTTED :
			{
				borderStyle = "dashed";
				borderWidth = 1;
				break;
			}
			case JRGraphicElement.PEN_4_POINT :
			{
				borderStyle = "solid";
				borderWidth = 4;
				break;
			}
			case JRGraphicElement.PEN_2_POINT :
			{
				borderStyle = "solid";
				borderWidth = 2;
				break;
			}
			case JRGraphicElement.PEN_THIN :
			{
				borderStyle = "solid";
				borderWidth = 1;//FIXMEODT can do better
				break;
			}
			case JRGraphicElement.PEN_NONE :
			{
				break;
			}
			case JRGraphicElement.PEN_1_POINT :
			default :
			{
				borderStyle = "solid";
				borderWidth = 1;
				break;
			}
		}

		if (borderWidth > 0)
		{
			styleWriter.write(" fo:border-");
			styleWriter.write(side);
			styleWriter.write("=\"");
			styleWriter.write(String.valueOf(Utility.translatePixelsToInchesWithNoRoundOff(borderWidth)));
			styleWriter.write("in ");
			styleWriter.write(borderStyle); 
			styleWriter.write(" #");
			String hexa = Integer.toHexString(borderColor.getRGB() & JROdtGridExporter.colorMask).toUpperCase();
			hexa = ("000000" + hexa).substring(hexa.length());
			styleWriter.write(hexa);
			styleWriter.write("\"");
		}

		if (padding > 0)
		{
			styleWriter.write(" fo:padding-");
			styleWriter.write(side);
			styleWriter.write("=\"");
			styleWriter.write(String.valueOf(Utility.translatePixelsToInchesWithNoRoundOff(padding)));
			styleWriter.write("\"");
		}
	}

	public void buildCellStyleFooter() throws IOException 
	{
		styleWriter.append("/>\n");
		styleWriter.append(" </style:style>\n");
	}
	
	public void buildCellHeader(int colSpan, int rowSpan) throws IOException 
	{
		String cellName = tableName + "_cell_" + cellCounter;
		//FIXMEODT officevalue bodyWriter.write("<table:table-cell office:value-type=\"string\"");
		bodyWriter.write("<table:table-cell");
		bodyWriter.write(" table:style-name=\"" + cellName + "\"");
		if (colSpan > 1)
			bodyWriter.write(" table:number-columns-spanned=\"" + colSpan + "\"");
		if (rowSpan > 1)
			bodyWriter.write(" table:number-rows-spanned=\"" + rowSpan + "\"");
		
		bodyWriter.write(">\n");
	}

	public void buildCellFooter() throws IOException {
		bodyWriter.write("</table:table-cell>\n");
	}
	
}