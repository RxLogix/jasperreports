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

import net.sf.jasperreports.engine.JRPropertiesUtil;
import net.sf.jasperreports.engine.JasperReportsContext;

/**
 * @author Lucian Chirita (lucianc@users.sourceforge.net)
 */
public class ValueClassFilter extends AbstractClassFilter
{
	public static final String PROPERTY_PREFIX_CLASS_WHITELIST =
			JRPropertiesUtil.PROPERTY_PREFIX + "value.deserialization.class.whitelist.";

	public static final String EXCEPTION_MESSAGE_KEY_CLASS_NOT_VISIBLE = "value.deserialization.class.not.visible";

	public ValueClassFilter(JasperReportsContext jasperReportsContext)
	{
		super(jasperReportsContext);
	}

	@Override
	protected String getClassFilterEnabledPropertyName()
	{
		return DeserializationClassFilter.PROPERTY_CLASS_FILTER_ENABLED;
	}

	@Override
	protected String getClassWhitelistPropertyPrefix()
	{
		return PROPERTY_PREFIX_CLASS_WHITELIST;
	}

	@Override
	protected String getClassNotVisibleExceptionMessageKey()
	{
		return EXCEPTION_MESSAGE_KEY_CLASS_NOT_VISIBLE;
	}

	@Override
	protected void addHardcodedWhitelist(StandardClassWhitelist whitelist)
	{
	}
}
