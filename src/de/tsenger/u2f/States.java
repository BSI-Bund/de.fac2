/*
*******************************************************************************
*  This file is part of the
*  
*  de.fac2 - FIDO U2F Authenticator Applet v1.0
*  copyright (c) 2017 Tobias Senger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*******************************************************************************
*/

package de.tsenger.u2f;

/**
 * @author Tobias Senger
 * @version 1.0
 *
 */
public class States {
	
	protected static final short UNINITIALIZED =  (short) 0xB4B4;
	protected static final short READY_FOR_USE =  (short) 0x5A5A; 
	protected static final short DELIVERY_STATE = (short) 0x6969; 
	
}
