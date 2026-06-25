/*
 * JasperReports - Free Java Reporting Library.
 * Copyright (C) 2001 - 2025 Cloud Software Group, Inc. All rights reserved.
 * http://www.jaspersoft.com
 *
 * Unless you have purchased a commercial license agreement from Jaspersoft,
 * the following license terms apply:
 *
 * This program is part of JasperReports.
 *
 * JasperReports is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * JasperReports is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with JasperReports. If not, see <http://www.gnu.org/licenses/>.
 */
package net.sf.jasperreports.engine.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;

import net.sf.jasperreports.engine.JRPropertiesUtil;
import net.sf.jasperreports.engine.JasperReportsContext;

/**
 * A subclass of {@link ObjectInputStream} that filters the classes encountered
 * in the stream against a configurable {@link DeserializationFilter}, and that
 * optionally enforces the deserialization byte count limit.
 *
 * @author Teodor Danciu (teodord@users.sourceforge.net)
 */
public class FilteredObjectInputStream extends ObjectInputStream
{
	protected final JasperReportsContext jasperReportsContext;

	private DeserializationFilter deserializationFilter;

	/**
	 * Creates an object input stream that reads data from the specified
	 * {@link InputStream}.
	 *
	 * @param in the input stream to read data from
	 * @throws IOException
	 * @see ObjectInputStream#ObjectInputStream(InputStream)
	 */
	public FilteredObjectInputStream(JasperReportsContext jasperReportsContext, InputStream in,
			DeserializationFilter deserializationFilter) throws IOException
	{
		super(wrapInputStream(jasperReportsContext, in));

		this.jasperReportsContext = jasperReportsContext;
		this.deserializationFilter = deserializationFilter;
	}

	private static InputStream wrapInputStream(JasperReportsContext jasperReportsContext, InputStream is)
	{
		String byteCountLimitProp = JRPropertiesUtil.getInstance(jasperReportsContext).getProperty(
				ContextClassLoaderObjectInputStream.PROPERTY_BYTE_COUNT_LIMIT);
		long byteCountLimit = (byteCountLimitProp == null || byteCountLimitProp.trim().length() == 0)
				? 0L : Long.parseLong(byteCountLimitProp.trim());
		return byteCountLimit == 0 ? is : new CountInputStream(is, byteCountLimit);
	}

	public JasperReportsContext getJasperReportsContext()
	{
		return jasperReportsContext;
	}

	@Override
	protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException,
			ClassNotFoundException
	{
		if (deserializationFilter.isFilteringEnabled())
		{
			String className = desc.getName();
			if (className.startsWith("["))
			{
				if (className.endsWith(";"))
				{
					className = className.substring(className.lastIndexOf("[L") + 2, className.length() - 1);
				}
				else
				{
					className = className.substring(className.lastIndexOf("[") + 1);
				}
			}
			deserializationFilter.checkClassVisibility(className);
		}

		return super.resolveClass(desc);
	}
}
