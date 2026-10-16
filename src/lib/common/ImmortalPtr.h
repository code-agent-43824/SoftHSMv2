/*
 * Copyright (c) 2026 code-agent-43824
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 ImmortalPtr.h

 The owner of a process-wide object that is not destroyed when the process
 exits.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_IMMORTALPTR_H
#define _SOFTHSM_V2_IMMORTALPTR_H

// The destructor is trivial on purpose: nothing is registered with atexit for
// it, so a PKCS #11 call that arrives after main has returned still finds the
// object alive. pkcs11-provider makes such calls from OpenSSL's own exit
// handler, which runs after everything this library registered when it was
// loaded (docs/JOURNAL.md, 17 October 2026). reset() destroys the object it
// held, which is how C_Finalize releases it; a library unloaded without
// C_Finalize leaves it behind.
template <class T>
class ImmortalPtr
{
public:
	constexpr ImmortalPtr() : pointer(nullptr) { }
	ImmortalPtr(const ImmortalPtr&) = delete;
	ImmortalPtr& operator=(const ImmortalPtr&) = delete;

	T* get() const { return pointer; }
	T* operator->() const { return pointer; }

	void reset(T* replacement = nullptr)
	{
		T* previous = pointer;
		pointer = replacement;
		delete previous;
	}

private:
	T* pointer;
};

#endif // !_SOFTHSM_V2_IMMORTALPTR_H
