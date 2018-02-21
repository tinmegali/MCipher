package com.tinmegali.security.mcipher.testClasses;

/**
 * com.tinmegali.security.mcipher.testClasses | MCipher
 * __________________________________
 * Created by tinmegali
 * 19/02/2018
 *
 * @see <a href="http://www.tinmegali.com">tinmegali.com</a>
 * @see <a href="http://github.com/tinmegali">github</a>
 * ___________________________________
 */

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.tinmegali.security.mcipher.MCipherUtils;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;


@RunWith(AndroidJUnit4.class)
public class MCipherUtilsTests {

    final String s1 = "a string";
    final String s2 = "kahsdkjhakjsdhakjshdkjahdkjahskjdhaskjdhakjsdhaskdh";
    final String s3 = "kahsdkjhakjsdhakjshdk jahdkjahsk jdhaskjdhakjsdhaskdslks lkdlkjfkjfkgjdkfhgkjdhfkgjhdkfjghkdfjhgkjhieuhriuehi ehrgiuehrighergh";
    final String s4 = s3 + s3 + s3 + s3;
    Context appContext;

    @Before
    public void setup() throws Exception {
        appContext = InstrumentationRegistry.getTargetContext();
    }

    @Test
    public void encodeDecodeTest() throws Exception {
        encodeDecode(s1);
        encodeDecode(s2);
        encodeDecode(s3);
        encodeDecode(s4);
    }

    private void encodeDecode(String s) {
        byte[] decoded1 = MCipherUtils.decode( s );
        assertNotNull( decoded1 );
        String enc1 = MCipherUtils.encodeToStr( decoded1 );

        assertNotNull( enc1 );
        assertTrue( String.format("%s:%s",s,enc1), s.equals( enc1 ) );
    }

}
