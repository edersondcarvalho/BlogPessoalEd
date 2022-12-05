package com.generation.blogpessoal.SERVICE;

import com.generation.blogpessoal.model.Usuario;
import com.generation.blogpessoal.model.UsuarioLogin;
import com.generation.blogpessoal.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.Charset;
import org.apache.commons.codec.binary.Base64;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

@Service
public class UsuarioService {
    @Autowired
    private UsuarioRepository usuarioRepository;

    public Optional<Usuario> cadastrarUsiario(Usuario usuario)
    {
        if (usuarioRepository.findByUsuario(usuario.getUsuario()).isPresent()) {

            usuario.setSenha(criptografarsenha(usuario.getSenha()));
            return  Optional.of(usuarioRepository.save(usuario));
        }
        return Optional.empty();

    }
    public Optional<Usuario> AtualizarUsiario(Usuario usuario)
    {
        if(usuarioRepository.findById(usuario.getId()).isPresent()) {

            Optional<Usuario> buscaUsuario = usuarioRepository.findByUsuario(usuario.getUsuario());

            if ( (buscaUsuario.isPresent()) && ( buscaUsuario.get().getId() != usuario.getId()))
                throw new ResponseStatusException(
                        HttpStatus.BAD_REQUEST, "Usuário já existe!", null);

            usuario.setSenha(criptografarsenha(usuario.getSenha()));

            return Optional.ofNullable(usuarioRepository.save(usuario));

        }

        return Optional.empty();
    }
    public  Optional<UsuarioLogin> autenticarUsuario(Optional<UsuarioLogin> usuarioLogin)
    {
        Optional<Usuario> usuario = usuarioRepository.findByUsuario(usuarioLogin.get().getUsuario());
        if(usuario.isPresent())
        {
            if(comparaSenhas(usuarioLogin.get().getSenha(),usuario.get().getSenha()))
            {
                usuarioLogin.get().setId(usuario.get().getId());
                usuarioLogin.get().setNome(usuario.get().getNome());
                usuarioLogin.get().setFoto(usuario.get().getFoto());
                usuarioLogin.get().setToken(gerarToken(usuarioLogin.get().getUsuario(),usuarioLogin.get().getSenha()));
                usuarioLogin.get().setSenha(usuario.get().getSenha());
                return usuarioLogin;
            }

        }
        return Optional.empty();
    }

    private String gerarToken(String usuario, String senha) {
        String token = usuario + ":" + senha;
        byte[] tokenBase64 = Base64.encodeBase64(token.getBytes(Charset.forName("US-ASCII")));
        return  "Basic" + new String(tokenBase64);
    }


    private boolean comparaSenhas(String senhaDigitada, String senhaBanco) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        return encoder.matches(senhaDigitada,senhaBanco);

    }

    private  String criptografarsenha(String senha)
    {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        return  encoder.encode(senha);

    }

}
