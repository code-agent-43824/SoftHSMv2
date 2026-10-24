/*
 * Copyright (c) 2026 code-agent-43824
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED.
 */

#ifndef _SOFTHSM_V2_GOST2012TESTS_H
#define _SOFTHSM_V2_GOST2012TESTS_H

#include "config.h"
#include <cppunit/extensions/HelperMacros.h>

class GOST2012Tests : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(GOST2012Tests);
#ifdef WITH_GOST_3411_2012
	CPPUNIT_TEST(testStreebog256);
#endif
#ifdef WITH_GOST_3411_2012_512
	CPPUNIT_TEST(testStreebog512);
#endif
#ifdef WITH_GOST_3410_2012_256
	CPPUNIT_TEST(testKeyGeneration);
	CPPUNIT_TEST(testSigningAndVerification);
	CPPUNIT_TEST(testKEG);
#endif
	CPPUNIT_TEST_SUITE_END();

public:
#ifdef WITH_GOST_3411_2012
	void testStreebog256();
#endif
#ifdef WITH_GOST_3411_2012_512
	void testStreebog512();
#endif
#ifdef WITH_GOST_3410_2012_256
	void testKeyGeneration();
	void testSigningAndVerification();
	void testKEG();
#endif
};

#endif // _SOFTHSM_V2_GOST2012TESTS_H
