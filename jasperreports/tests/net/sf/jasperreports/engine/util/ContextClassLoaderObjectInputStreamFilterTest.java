/*
 * JasperReports - Free Java Reporting Library.
 * Copyright (C) 2001 - 2016 TIBCO Software Inc. All rights reserved.
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.UUID;

import net.sf.jasperreports.engine.JRRuntimeException;
import net.sf.jasperreports.engine.SimpleJasperReportsContext;

import org.testng.annotations.Test;

/**
 * Reproducer for CVE-2025-10492 — uncontrolled deserialization of arbitrary
 * classes through {@link ContextClassLoaderObjectInputStream}.
 * <p>
 * Without the deserialization class filter, an attacker who controls a
 * <code>.jaser</code> or other JR-loaded serialized payload can have any
 * Serializable class on the classpath instantiated and its custom
 * <code>readObject</code> executed, leading to remote code execution.
 */
public class ContextClassLoaderObjectInputStreamFilterTest
{
	private static final String FILTER_ENABLED_PROPERTY =
			"net.sf.jasperreports.deserialization.class.filter.enabled";
	private static final String BYTE_COUNT_LIMIT_PROPERTY =
			"net.sf.jasperreports.deserialization.byte.count.limit";
	private static final String EXCEPTION_KEY_NOT_VISIBLE =
			"deserialization.class.not.visible";
	private static final String EXCEPTION_KEY_BYTE_COUNT_EXCEEDED =
			"deserialization.byte.count.limit.exceeded";

	/**
	 * Stand-in for an RCE gadget. Demonstrates that arbitrary Serializable
	 * classes are resolved and have their <code>readObject</code> invoked
	 * through CCLOIS when no class filter is in place.
	 */
	public static class EvilGadget implements Serializable
	{
		private static final long serialVersionUID = 1L;
		public static volatile boolean executed;

		private void readObject(java.io.ObjectInputStream in)
				throws IOException, ClassNotFoundException
		{
			in.defaultReadObject();
			executed = true;
		}
	}

	@Test
	public void filterDisabled_gadgetExecutes() throws IOException, ClassNotFoundException
	{
		EvilGadget.executed = false;
		SimpleJasperReportsContext ctx = new SimpleJasperReportsContext();
		ctx.setProperty(FILTER_ENABLED_PROPERTY, "false");

		byte[] bytes = serialize(new EvilGadget());
		ContextClassLoaderObjectInputStream in =
				new ContextClassLoaderObjectInputStream(ctx, new ByteArrayInputStream(bytes));
		try
		{
			Object read = in.readObject();
			assert read instanceof EvilGadget;
		}
		finally
		{
			in.close();
		}
		assert EvilGadget.executed : "EvilGadget.readObject should run when filter is disabled";
	}

	@Test
	public void filterEnabled_gadgetBlocked() throws IOException
	{
		EvilGadget.executed = false;
		SimpleJasperReportsContext ctx = new SimpleJasperReportsContext();
		ctx.setProperty(FILTER_ENABLED_PROPERTY, "true");

		byte[] bytes = serialize(new EvilGadget());
		ContextClassLoaderObjectInputStream in =
				new ContextClassLoaderObjectInputStream(ctx, new ByteArrayInputStream(bytes));
		try
		{
			in.readObject();
			assert false : "Expected JRRuntimeException for non-whitelisted class";
		}
		catch (JRRuntimeException e)
		{
			assert EXCEPTION_KEY_NOT_VISIBLE.equals(e.getMessageKey()) :
					"Unexpected message key: " + e.getMessageKey();
		}
		catch (ClassNotFoundException e)
		{
			throw new AssertionError("Filter should reject the class before ClassNotFoundException is raised");
		}
		finally
		{
			in.close();
		}
		assert !EvilGadget.executed : "EvilGadget.readObject must not run when filter blocks the class";
	}

	@Test
	public void filterEnabled_whitelistedClassPasses() throws IOException, ClassNotFoundException
	{
		SimpleJasperReportsContext ctx = new SimpleJasperReportsContext();
		ctx.setProperty(FILTER_ENABLED_PROPERTY, "true");

		UUID original = UUID.randomUUID();
		byte[] bytes = serialize(original);
		ContextClassLoaderObjectInputStream in =
				new ContextClassLoaderObjectInputStream(ctx, new ByteArrayInputStream(bytes));
		try
		{
			Object read = in.readObject();
			assert original.equals(read) : "Whitelisted UUID should round-trip";
		}
		finally
		{
			in.close();
		}
	}

	@Test
	public void byteCountLimit_triggers() throws IOException
	{
		SimpleJasperReportsContext ctx = new SimpleJasperReportsContext();
		// disable class filtering so the byte-count limit is what we measure
		ctx.setProperty(FILTER_ENABLED_PROPERTY, "false");
		ctx.setProperty(BYTE_COUNT_LIMIT_PROPERTY, "8");

		byte[] bytes = serialize(UUID.randomUUID());
		ContextClassLoaderObjectInputStream in =
				new ContextClassLoaderObjectInputStream(ctx, new ByteArrayInputStream(bytes));
		try
		{
			in.readObject();
			assert false : "Expected JRRuntimeException due to byte limit";
		}
		catch (JRRuntimeException e)
		{
			assert EXCEPTION_KEY_BYTE_COUNT_EXCEEDED.equals(e.getMessageKey()) :
					"Unexpected message key: " + e.getMessageKey();
		}
		catch (ClassNotFoundException e)
		{
			throw new AssertionError(e);
		}
		finally
		{
			in.close();
		}
	}

	private static byte[] serialize(Object obj) throws IOException
	{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ObjectOutputStream out = new ObjectOutputStream(baos);
		try
		{
			out.writeObject(obj);
		}
		finally
		{
			out.close();
		}
		return baos.toByteArray();
	}
}
