package customer;

import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

public class CustomerControllerTest {

    CustomerService service = Mockito.mock(CustomerService.class);

    MockMvc mvc = MockMvcBuilders
            .standaloneSetup(new CustomerController(service))
            .build();

    @Test
    public void doesNotFindCustomerByUnknownCreditCard() throws Exception {
        mvc
            .perform(MockMvcRequestBuilders.get("/byCreditCard/123")
                    .header("Accept", "*/*"))
            .andDo(MockMvcResultHandlers.print())
            .andExpect(MockMvcResultMatchers.status().is(404));
    }
}
