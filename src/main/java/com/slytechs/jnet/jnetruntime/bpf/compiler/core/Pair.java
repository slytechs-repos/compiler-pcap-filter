/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
 *
 * Licensed under the Sly Technologies Free License (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.slytechs.com/free-license-text
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.slytechs.jnet.jnetruntime.bpf.compiler.core;

/**
 * Represents a pair of values, with one value of type {@code T1} and the other
 * of type {@code T2}. This interface provides a convenient way to group two
 * related values together.
 * 
 * <p>
 * Pairs are commonly used to return two values from a method or to hold a pair
 * of related objects.
 * </p>
 *
 * @param <T1> the type of the first value
 * @param <T2> the type of the second value
 * 
 *             <p>
 *             Example usage:
 *             </p>
 * 
 *             <pre>{@code
 * Pair<String, Integer> pair = Pair.of("Hello", 42);
 * System.out.println("First: " + pair.arg1()); // Outputs "Hello"
 * System.out.println("Second: " + pair.arg2()); // Outputs 42
 * }</pre>
 * 
 * @author Mark Bednarczyk
 */
public interface Pair<T1, T2> {

	/**
	 * Creates a new {@code Pair} with the specified values.
	 *
	 * @param <T1>   the type of the first value
	 * @param <T2>   the type of the second value
	 * @param value1 the first value
	 * @param value2 the second value
	 * @return a new {@code Pair} containing the specified values
	 */
	static <T1, T2> Pair<T1, T2> of(T1 value1, T2 value2) {
		return new Pair<T1, T2>() {

			@Override
			public T1 value1() {
				return value1;
			}

			@Override
			public T2 value2() {
				return value2;
			}
		};
	}

	/**
	 * Returns the first value of the pair.
	 *
	 * @return the first value of type {@code T1}
	 */
	T1 value1();

	/**
	 * Returns the second value of the pair.
	 *
	 * @return the second value of type {@code T2}
	 */
	T2 value2();

}
