/******************************************************************************
 * Icinga 2                                                                   *
 * Copyright (C) 2012-2016 Icinga Development Team (https://www.icinga.org/)  *
 *                                                                            *
 * This program is free software; you can redistribute it and/or              *
 * modify it under the terms of the GNU General Public License                *
 * as published by the Free Software Foundation; either version 2             *
 * of the License, or (at your option) any later version.                     *
 *                                                                            *
 * This program is distributed in the hope that it will be useful,            *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              *
 * GNU General Public License for more details.                               *
 *                                                                            *
 * You should have received a copy of the GNU General Public License          *
 * along with this program; if not, write to the Free Software Foundation     *
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.             *
 ******************************************************************************/

#include "remote/apiuser.hpp"
#include "remote/apiuser.tcpp"
#include "base/configtype.hpp"

using namespace icinga;

REGISTER_TYPE(ApiUser);

/* Return split password hash as Dictionary */
Dictionary::Ptr ApiUser::GetPasswordDict(void)
{
	String passwd = this->GetPasswordHash();
	if (passwd.IsEmpty() || passwd[0] != '$')
		return NULL;

	String::SizeType salt_begin = passwd.FindFirstOf('$', 1);
	String::SizeType passwd_begin = passwd.FindFirstOf('$', salt_begin+1);

	if (salt_begin == String::NPos || salt_begin == 1 || passwd_begin == String::NPos)
		return NULL;

	Dictionary::Ptr passwd_dict = new Dictionary();
	passwd_dict->Set("algorithm", passwd.SubStr(1, salt_begin-1));
	passwd_dict->Set("salt", passwd.SubStr(salt_begin+1, passwd_begin - salt_begin - 1));
	passwd_dict->Set("password", passwd.SubStr(passwd_begin+1));

	return passwd_dict;
}
ApiUser::Ptr ApiUser::GetByClientCN(const String& cn)
{
	for (const ApiUser::Ptr& user : ConfigType::GetObjectsByType<ApiUser>()) {
		if (user->GetClientCN() == cn)
			return user;
	}

	return ApiUser::Ptr();
}
