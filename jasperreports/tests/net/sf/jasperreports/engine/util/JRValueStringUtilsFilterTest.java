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

import net.sf.jasperreports.engine.JRRuntimeException;
import net.sf.jasperreports.engine.SimpleJasperReportsContext;

import org.testng.annotations.Test;

/**
 * Reproducer for CVE-2026-6009 — uncontrolled deserialization of arbitrary
 * classes through report value strings.
 * <p>
 * {@link JRValueStringUtils} deserializes BASE64-encoded value strings of
 * non-built-in types through a plain <code>ObjectInputStream</code>. Without
 * the value-deserialization class filter, an attacker who controls a value
 * string (e.g. a default value in a <code>.jasper</code> file or a subreport
 * value) can have any Serializable class on the classpath instantiated and its
 * custom <code>readObject</code> executed, leading to remote code execution.
 * <p>
 * The fix routes value deserialization through {@link FilteredObjectInputStream}
 * using a {@link ValueClassFilter}, which is gated by the existing
 * <code>net.sf.jasperreports.deserialization.class.filter.enabled</code> flag
 * (default <code>true</code>) and a dedicated
 * <code>net.sf.jasperreports.value.deserialization.class.whitelist.*</code>
 * namespace that is empty by default.
 */
public class JRValueStringUtilsFilterTest
{
	private static final String FILTER_ENABLED_PROPERTY =
			"net.sf.jasperreports.deserialization.class.filter.enabled";
	private static final String VALUE_WHITELIST_PROPERTY_PREFIX =
			"net.sf.jasperreports.value.deserialization.class.whitelist.";
	private static final String EXCEPTION_KEY_NOT_VISIBLE =
			"value.deserialization.class.not.visible";

	/**
	 * Stand-in for an RCE gadget. Demonstrates that arbitrary Serializable
	 * classes are resolved and have their <code>readObject</code> invoked
	 * through value deserialization when no class filter is in place.
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
		FilteredObjectInputStream in = new FilteredObjectInputStream(
				ctx, new ByteArrayInputStream(bytes), new ValueClassFilter(ctx));
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
		FilteredObjectInputStream in = new FilteredObjectInputStream(
				ctx, new ByteArrayInputStream(bytes), new ValueClassFilter(ctx));
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
	public void filterEnabled_inheritsSharedDeserializationWhitelist() throws IOException, ClassNotFoundException
	{
		// AbstractClassFilter loads the shared DeserializationClassWhitelist extensions for every
		// filter (upstream behaviour), so a class already on the curated report whitelist
		// (e.g. java.lang.String) is permitted through value deserialization too. The fix tightens
		// the previously-unfiltered value path down to that curated whitelist; arbitrary attacker
		// classes such as EvilGadget remain blocked (see filterEnabled_gadgetBlocked).
		SimpleJasperReportsContext ctx = new SimpleJasperReportsContext();
		ctx.setProperty(FILTER_ENABLED_PROPERTY, "true");

		String original = "a plain string";
		byte[] bytes = serialize(original);
		FilteredObjectInputStream in = new FilteredObjectInputStream(
				ctx, new ByteArrayInputStream(bytes), new ValueClassFilter(ctx));
		try
		{
			Object read = in.readObject();
			assert original.equals(read) : "Report-whitelisted java.lang.String should round-trip";
		}
		finally
		{
			in.close();
		}
	}

	@Test
	public void filterEnabled_valueWhitelistNamespaceHonored() throws IOException, ClassNotFoundException
	{
		// EvilGadget is not on any report whitelist; whitelisting it through the value-specific
		// namespace must let it pass, proving the value.* prefix is wired into ValueClassFilter.
		EvilGadget.executed = false;
		SimpleJasperReportsContext ctx = new SimpleJasperReportsContext();
		ctx.setProperty(FILTER_ENABLED_PROPERTY, "true");
		ctx.setProperty(VALUE_WHITELIST_PROPERTY_PREFIX + "test", EvilGadget.class.getName());

		byte[] bytes = serialize(new EvilGadget());
		FilteredObjectInputStream in = new FilteredObjectInputStream(
				ctx, new ByteArrayInputStream(bytes), new ValueClassFilter(ctx));
		try
		{
			Object read = in.readObject();
			assert read instanceof EvilGadget : "Value-whitelisted class should round-trip";
		}
		finally
		{
			in.close();
		}
		assert EvilGadget.executed : "Value-whitelisted class should deserialize normally";
	}

	@Test
	public void valueStringRoundTrip_blocksGadgetByDefault()
	{
		// end-to-end through the public API, using the default context (filter enabled by default)
		EvilGadget.executed = false;
		String data = JRValueStringUtils.serialize(EvilGadget.class.getName(), new EvilGadget());
		try
		{
			JRValueStringUtils.deserialize(EvilGadget.class.getName(), data);
			assert false : "Expected JRRuntimeException for non-whitelisted value class";
		}
		catch (JRRuntimeException e)
		{
			assert EXCEPTION_KEY_NOT_VISIBLE.equals(e.getMessageKey()) :
					"Unexpected message key: " + e.getMessageKey();
		}
		assert !EvilGadget.executed : "EvilGadget.readObject must not run through JRValueStringUtils";
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
